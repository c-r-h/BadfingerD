/* ========================================================================== **
 *                                badfingerd.c
 *
 * Copyright:
 *  Copyright (C) 2010 by Christopher R. Hertel
 *
 * Email: crh@ubiqx.mn.org
 *
 * $Id: badfingerd.c; 2020-04-02 22:25:09 -0500; Christopher R. Hertel$
 *
 * -------------------------------------------------------------------------- **
 *
 * Description:
 *  A "finger" daemon that does not even attempt to be RFC 1288 compliant.
 *
 * -------------------------------------------------------------------------- **
 *
 * License:
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful.
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * -------------------------------------------------------------------------- **
 *
 * Notes:
 *
 *  Upon recept of a TCP connection request (on port 79, by default), this
 *  program ignores the content of the incoming request entirely.  Instead,
 *  it runs a pre-specified shell command and redirects the output back over
 *  the TCP connection.  When EOF is reached, or when the specified maximum
 *  number of bytes has been returned to the caller, the TCP connection is
 *  closed.
 *
 *  To compile:
 *    cc -o badfingerd badfingerd.c
 *
 * Bugs:
 *
 *  - There is currently no error checking done when accepting the
 *    remote connecton, or when popen()ing the stream connection for
 *    command output.
 *
 *  - The code now supports setting effective uid and gid.  The ability to
 *    set and reset the user and group context is tested at startup, but
 *    at run-time we currently ignore the return value of seteuid(2) and
 *    setegid(2).  This is probably safe, because the only listed errors
 *    are:
 *      EINVAL  - The uid or gid is invalid.
 *      EPERM   - The process does not have the required permissions.
 *    We test for both of these conditions at startup, so they "shouldn't"
 *    happen. <cough>
 *
 *    The fix is to implement logging, as described elsewhere in this
 *    whiney buglist, so that we can explain what went wrong before bailing
 *    out.
 *
 *  - This program is currently quite rudimentary.  For completeness:
 *
 *    + There should be a /var/run/badfingerd.pid file if we run as
 *      root on the default port.  (/var/run/badfingerd-<port>.pid
 *      otherwise?)
 *
 *    + The daemon should send its own errors to syslog or a log file by
 *      default.  If running in the foreground, it should continue to
 *      send errors to <stderr>.
 *
 *    + We should capture <stderr> from the subprocess that runs the
 *      shell command.  Those errors should also be directed to syslog,
 *      a log file, or to the main process' <stderr> if running in the
 *      foreground.
 *
 *      It is possible to write our own equivalent of popen(3) that
 *      will return two file pointers, one for <stdout> and one for
 *      <stderr>.  See: http://snippets.dzone.com/tag/popen
 *
 *    + It should be possible to run this command from [x]inetd.  The
 *      expected load in some environments would be quite low and running
 *      as a full-time daemon is a waste of resources.
 *
 *    + We should be able to bind to a specified interface.
 *
 *    + We should be able to handle IPv4 and/or IPv6.
 *
 *    + There should be a management interface of some sort.  At minimum,
 *      the daemon should exit gracefully if it receives a SIGHUP or
 *      SIGTERM.  Statistics collection and logging would also be useful.
 *
 *    + It would be interesting if badfingerd were multi-threaded.
 *      One thread per TCP connection, with an enforced maximum number of
 *      threads.  Perhaps a thread pool.  As it is, connection handling is
 *      basically serial.
 *
 *  - Some versions of finger restrict the number of characters of
 *    received data that are displayed.  One work-around is to use
 *    netcat (nc) or telnet instead:
 *      $ nc <remote host> 79
 *      $ telnet <remote host> 79
 *
 * ========================================================================== **
 */

#include <stdio.h>      /* Standard I/O stuff.              */
#include <stdlib.h>     /* For EXIT_SUCCESS, etc.           */
#include <stdint.h>     /* Extended integer types.          */
#include <stdbool.h>    /* Standard boolean type.           */
#include <unistd.h>     /* For getopt(3), setuid(2), etc.   */
#include <errno.h>      /* The errno variable.              */
#include <string.h>     /* For strerror(3), strcat(3), etc. */
#include <stdarg.h>     /* Variable argument lists.         */

#include <signal.h>     /* For sigaction(2).                */
#include <netinet/in.h> /* Network address structures.      */
#include <arpa/inet.h>  /* Needed by inet_ntoa(3).          */
#include <sys/socket.h> /* For listen(2) and accept(2).     */
#include <netdb.h>      /* For getservbyname(3).            */
#include <sys/types.h>  /* For gid_t & other system types.  */
#include <pwd.h>        /* For getpwnam(3) and getpwuid(3). */
#include <grp.h>        /* For getgrnam(3) and getgrgid(3). */


/* -------------------------------------------------------------------------- **
 * Typedefs:
 *
 *  idMatrix  - Store both the original [uid,gid] pair, and the pair to use
 *              when spawning the sub-process that will perform the command
 *              stored in <CmdStr> (see below).
 */

typedef struct
  {
  uid_t origUid;  /* The original UID.  */
  gid_t origGid;  /* The original GID.  */
  uid_t safeUid;  /* The UID to become in order to execute the command. */
  gid_t safeGid;  /* The GID to become in order to execute the command. */
  } idMatrix;


/* -------------------------------------------------------------------------- **
 * Macros:
 *
 *  Err()   - This is a conceited little macro that simply replaces
 *            fprintf( stderr, ... ) with something shorter and easier
 *            to type.
 * StrErrno - Shorthand macro to return the error text associated
 *            with <errno>.
 */

#define Err( ... ) (void)fprintf( stderr, __VA_ARGS__ )
#define StrErrno strerror( errno )


/* -------------------------------------------------------------------------- **
 * Defined Constants:
 *
 *  bSIZE     - The block size used for transferring data from the shell's
 *              <stdout> to the TCP connection.  See <Serve()>, below.
 */

#define bSIZE 1024


/* -------------------------------------------------------------------------- **
 * Global Constants:
 *
 *  Copyright   - Copyright information.
 *  Revision    - Revision string, generated by revision control.
 *  ID          - Longer revision string.
 *
 *  HelpMsg     - The program help message.
 */

static const char *Copyright
                = "Copyright (c) 2011 by Christopher R. Hertel";
static const char *Revision
                = "$Revision: 5 $";
static const char *ID
                = "$Id: badfingerd.c; 2020-04-02 22:25:09 -0500; Christopher R. Hertel$";

static const char *HelpMsg[] =
  {
  "  Available Options:",
  "  -d <dir>   Change directory to <dir>.",
  "  -f         Run in the foreground, not as a daemon.",
  "  -g <group> After startup, change the process Group ID to that of <group>.",
  "  -h         Produce this useful help message, then exit.",
  "  -m <max>   Maximum number of bytes to return.  Default = 0"
  " (unlimited).",
  "  -o         Run once; exit after one connection.",
  "  -p <port>  Listen on the specified port number.  Default = 79.",
  "  -t         Test:  Execute the command in the foreground, then exit.",
  "  -u <user>  After startup, change the process User ID to that of <user>",
  "             (<user> may be given as <user>:<group>).",
  "  -V         Output version information.",
  "  -v         Be verbose.  Add more -v's for more verbosity.",
  NULL
  };


/* -------------------------------------------------------------------------- **
 * Global Variables:
 *
 *  BeDaemon  - If true, run as a daemon.
 *  MaxDump   - Maximum number of bytes to return in response to a query.
 *  Singular  - Reply to only one connection, then exit.
 *  Port      - The port number on which to listen; default: 79 (fingerd).
 *  RunAs     - If non-NULL, this points to the UID/GID values to use.
 *  Verbosity - Controls the amount of diagnostic output provided.
 *  CmdStr    - Global pointer to the command string to run.  The string is
 *              read from the command line.
 */

static bool       BeDaemon  = true;
static uint32_t   MaxDump   = 0;
static bool       Singular  = false;
static uint16_t   Port      = 79;
static idMatrix  *RunAs     = NULL;
static int        Verbosity = 0;
static char      *CmdStr    = NULL;


/* -------------------------------------------------------------------------- **
 * Static Functions:
 */

static int SetEUidGid( void )
  /* ------------------------------------------------------------------------ **
   * Set the effective uid and gid to those specified on the command line.
   *
   *  Input:  <none>
   *
   *  Output: On success, zero (0) is returned.  On error, -1 is returned
   *          and <errno> is will be non-zero.  See seteuid(2) for possible
   *          <errno> values and their meaning.
   *
   * ------------------------------------------------------------------------ **
   */
  {
  if( NULL != RunAs )
    {
    errno = 0;
    if( (RunAs->origGid != RunAs->safeGid) && (0 > setegid( RunAs->safeGid )) )
      return( -1 );
    if( (RunAs->origUid != RunAs->safeUid) && (0 > seteuid( RunAs->safeUid )) )
      return( -1 );
    }
  return( 0 );
  } /* SetEUidGid */


static int UnsetEUidGid( void )
  /* ------------------------------------------------------------------------ **
   * Reset the effective uid and gid to those in effect at program start.
   * ------------------------------------------------------------------------ **
   */
  {
  if( NULL != RunAs )
    {
    errno = 0;
    if( (RunAs->origUid != RunAs->safeUid) && (0 > seteuid( RunAs->origUid )) )
      return( -1 );
    if( (RunAs->origGid != RunAs->safeGid) && (0 > setegid( RunAs->origGid )) )
      return( -1 );
    }
  return( 0 );
  } /* UnsetEUidGid */


static void Serve( const int sock )
  /* ------------------------------------------------------------------------ **
   * Respond to incoming requests.
   *
   *  Input:  sock  - Listening socket.
   *  Output: <none>
   *
   *  Notes:  This function may be run in daemon mode, so there is neither
   *          input from <stdin>, nor output to <stdout> or <stderr>.
   *
   * ------------------------------------------------------------------------ **
   */
  {
  int     newsock;
  FILE   *subStream;
  char    bufr[bSIZE];
  int64_t count;
  size_t  outcount;

  do
    {
    newsock = accept( sock, NULL, NULL );     /* Answer the call.         */
    (void)SetEUidGid();                       /* Set effective uid/gid.   */
    subStream = popen( CmdStr, "re" );        /* Capture command output.  */

    /* While there is either no limit, or until we reach the limit...
     */
    outcount = 0;
    while( (0 == MaxDump) || (outcount < MaxDump) )
      {
      count = (int64_t)fread( bufr, 1, bSIZE, subStream );
      outcount += (size_t)count;

      /* If there is a limit to the number of bytes requested,
       * enforce that limit.  Make sure the message sent ends
       * with a newline.
       */
      if( (MaxDump > 0) && (outcount >= MaxDump) )
        {
        count -= (int64_t)(outcount - MaxDump);
        bufr[count - 1] = '\n';
        }
      count = (int64_t)write( newsock, bufr, (size_t)count );

      /* If we read, or sent, less than bSIZE bytes this go-round,
       * then we have either reached EOF or the maximum output
       * limit (MaxDump).  It is also possible that write(2) returned
       * an error value (-1).  In any of those cases, we're done.
       */
      if( count < bSIZE )
        break;
      }

    /* Cleanup. */
    pclose( subStream );                      /* Close the subproc stream.  */
    close( newsock );                         /* Close the TCP connection.  */
    (void)UnsetEUidGid();                     /* Reset effective uid/gid.   */
    } while( !Singular );

  } /* Serve */


static void Fail( char *fmt, ... )
  /* ------------------------------------------------------------------------ **
   * Format and print a failure message on <stderr>, then exit the process.
   *
   *  Input:  fmt - Format string, as used in printf(), etc.
   *          ... - Variable parameter list.
   *
   *  Output: <none>
   *
   * ------------------------------------------------------------------------ **
   */
  {
  va_list ap;

  va_start( ap, fmt );
  (void)fprintf( stderr, "Failure: " );
  (void)vfprintf( stderr, fmt, ap );
  exit( EXIT_FAILURE );
  } /* Fail */


static void SetSignals( void )
  /* ------------------------------------------------------------------------ **
   * Set up signal handling.
   *
   *  Input:  <none>
   *
   *  Output: <none>
   *
   * ------------------------------------------------------------------------ **
   */
  {
  struct sigaction act[1];
  struct sigaction old_act[1];

  /* If the client closes its receiving half of the connection before or
   * during data transfer from the server, an out-of-band SIGPIPE will be
   * sent to the server process.  The default behavior is process
   * termination, which isn't what we want at all, so we'll just ignore
   * the signal and allow write(2) to return -1 to indicate the error.
   *
   * Note:  There is a bug in some versions of the Linux port of the
   *        OpenBSD NetCat (nc) program, under some versions of Ubuntu.
   *        If data is sent *to* the server, nc closes the connection
   *        after sending and fails to receive anything.  The symptom is
   *        that 'nc server 79' will work, but 'echo "foo" | nc server 79'
   *        will not.
   */
  act->sa_handler = SIG_IGN;
  if( sigaction( SIGPIPE, act, old_act ) < 0 )
    Fail( "Could not ignore SIGPIPE\n" );
  return;
  } /* SetSignals */


static void Spawn( void )
  /* ------------------------------------------------------------------------ **
   * Spawn a daemon process, which will take over control for us.
   *
   *  Input:  <none>
   *  Output: <none>
   *
   *  Notes:  If the child process is created successfully, the parent
   *          process is terminated using _exit(2).  This bypasses executing
   *          any functions registered with atexit(3) or on_exit(3).  This
   *          seems to be standard practice.  See:
   *            http://www.steve.org.uk/Reference/Unix/faq_2.html#SEC6
   *
   * ------------------------------------------------------------------------ **
   */
  {
  pid_t pid = fork();

  if( pid < 0 )   /* Error. */
    {
    Fail( "Cannot spawn child process; %s\n", StrErrno );
    }

  if( pid > 0 )   /* Parent process. */
    {
    Err( "Daemon process %d spawned.\n", pid );
    _exit( EXIT_SUCCESS );
    }

  /* Child process. */
  if( setsid() < 0 )
    {
    /* We should report an error...somehow. */
    exit( EXIT_FAILURE );
    }

  /* Close standard file descriptors.
   */
  close(  STDIN_FILENO );
  close( STDOUT_FILENO );
  close( STDERR_FILENO );
  return;
  } /* Spawn */


static int OpenSocket( in_addr_t if_addr )
  /* ------------------------------------------------------------------------ **
   * Open the IPv4 socket on which we will listen for connections.
   *
   *  Input:  if_addr - The IPv4 address representing the interface to which
   *                    to bind the socket. Use INADDR_ANY to bind to all
   *                    interfaces.
   *
   *  Output: The socket, bound to the desired interface and placed into
   *          passive (listen) mode.
   *
   *  Bugs:   This function only handles IPv4 addresses.  We should be able
   *          to open the socket on an IPv6 address instead or in addition.
   *
   * ------------------------------------------------------------------------ **
   */
  {
  int                sock;
  int                result;
  int                backlog;
  struct sockaddr_in v4_addr;
  int                yes[1] = { 1 };

  /* Create the socket.
   * Set the SO_REUSEADDR attribute on the socket before calling bind().
   */
  sock = socket( PF_INET, SOCK_STREAM, 0 );
  if( sock < 0 )
    Fail( "Cannot create IPv4 TCP socket; %s\n", StrErrno );
  if( setsockopt( sock, SOL_SOCKET, SO_REUSEADDR, yes, sizeof(int) ) < 0 )
    Fail( "Setting socket option SO_REUSEADDR; %s.\n", StrErrno );

  /* Bind the socket to the interface. */
  v4_addr.sin_family      = AF_INET;
  v4_addr.sin_port        = htons( Port );
  v4_addr.sin_addr.s_addr = if_addr;
  result = sizeof( struct sockaddr_in );
  result = bind( sock, (struct sockaddr *)(&v4_addr), (socklen_t)result );
  if( result < 0 )
    Fail( "Cannot bind IPv4 socket to address %s, port %d; %s\n",
          inet_ntoa( v4_addr.sin_addr ), Port, StrErrno );

  /* Set the socket to listen for connections (passive--as opposed
   * to making a connection, which is active).
   */
  backlog = ( Singular ) ? 1 : 12;
  if( listen( sock, backlog ) < 0 )
    Fail( "Cannot listen on port %d; %s.\n", Port, StrErrno );

  return( sock );
  } /* OpenSocket */


static int GetTcpPortNo( const char *pname )
  /* ------------------------------------------------------------------------ **
   * Use the input string to look up an entry in /etc/services.
   *
   *  Input:  pname - A string containing either a port number (as a string
   *                  of decimal numerals) or port name.
   *
   *  Output: The actual port number, or -1 on error.
   *
   *  Notes:  This function returns only TCP port assigments.
   *
   *          This function is a wrapper around getservbyname(3).  Note,
   *          however, that if the input string is a decimal numeric
   *          string that represents a valid port number, this function
   *          will return that number.  For example, if "1392" is passed
   *          in, and there is no matching entry in the /etc/services
   *          file, this function will still return the value 1392.
   *
   * ------------------------------------------------------------------------ **
   */
  {
  struct servent *MrBunter;
  bool            is_numeric = true;
  int             i;

  /* First, check /etc/services
   */
  MrBunter = getservbyname( pname, "tcp" );
  if( NULL != MrBunter )
    return( ntohs( (uint16_t)(MrBunter->s_port) ) );

  /* If we received a NULL response, we may still have
   * a valid numeric port number that simply isn't
   * defined in /etc/services.
   * Make sure it's a numeric string.
   */
  for( i = 0; ('\0' != pname[i]) && is_numeric; i++ )
    {
    if( ('0' > pname[i]) || (pname[i] > '9') )
      is_numeric = false;
    }
  if( !is_numeric )
    return( -1 );

  /* Numeric.  Translate it.
   */
  i = atoi( pname );
  if( (1 > i) || (i > 0xFFFF) )
    return( -1 );
  return( i );
  } /* GetTcpPortNo */


static void TestCmd( void )
  /* ------------------------------------------------------------------------ **
   * Test the user-supplied command string.
   *
   *  Input:  <none>
   *  Output: <none>
   *
   * ------------------------------------------------------------------------ **
   */
  {
  FILE   *subStream;
  char    bufr[bSIZE];
  ssize_t count;
  size_t  outcount = 0;

  (void)SetEUidGid();
  subStream = popen( CmdStr, "re" );          /* Capture command output. */

  while( (0 == MaxDump) || (outcount < MaxDump) )
    {
    count     = (ssize_t)fread( bufr, 1, bSIZE, subStream );
    outcount += (size_t)count;

    /* If there is a limit to the number of bytes requested,
     * enforce that limit.  Make sure the message sent ends
     * with a newline.
     */
    if( (MaxDump > 0) && (outcount >= MaxDump) )
      {
      count -= (ssize_t)(outcount - MaxDump);
      bufr[count - 1] = '\n';
      }
    count = (ssize_t)write( STDOUT_FILENO, bufr, (size_t)count );

    /* If we read, or sent, less than bSIZE bytes this go-round,
     * then we have either reached EOF or the maximum output
     * limit (MaxDump).  In either case, we're done.
     */
    if( count < bSIZE )
      break;
    }

  (void)UnsetEUidGid();
  exit( EXIT_SUCCESS );
  } /* TestCmd */


static void Usage( const char *progname, int status )
  /* ------------------------------------------------------------------------ **
   * Provide usage information, then exit.
   *
   *  Input:  progname  - Pointer to a string containing the program name.
   *          status    - Exit status to return.
   *
   *  Output: <none>
   *
   *  Notes:  <none>
   *
   * ------------------------------------------------------------------------ **
   */
  {
  int i;

  Err( "Usage: %s [options] <command string>\n", progname );
  for( i = 0; NULL != HelpMsg[i]; i++ )
    {
    (void)fputs( HelpMsg[i], stderr );
    (void)fputc( '\n', stderr );
    }

  exit( status );
  } /* Usage */


static int64_t AtoS64( const char *numstr )
  /* ------------------------------------------------------------------------ **
   * Quick conversion from string to 64-bit signed integer.
   *
   *  Input:  numstr  - Pointer to a string made up of decimal digits.
   *
   *  Output: A signed 64-bit integer.  Zero (0) is a valid result, but zero
   *          is also the default value returned if an error is encountered.
   *          Check <errno>.
   *
   *  Errors: On success, <errno> will be zero.  On error, <errno> will be
   *          set to a non-zero value.  Expect the following:
   *            ERANGE  - The resulting value was out of range.
   *            EINVAL  - The input was not, in whole or in part, a decimal
   *                      numeric string.
   *          See strtol(3) for more information.
   *
   *  Notes:  - Unlike ReadNumval(), below, we expect *all* of the
   *            characters in the string to be decimal numerics.  This
   *            function returns zero (0) and sets <errno> to EINVAL if a
   *            non-decimal character is encountered.
   *
   * ------------------------------------------------------------------------ **
   */
  {
  int64_t  result;
  char    *endptr;

  /* Well, let's give 'er a whirl.  */
  errno  = 0;
  result = (int64_t)strtol( numstr, &endptr, 10 );
  if( errno )
    return( 0 );

  /* Now validate.  */
  if( '\0' != *endptr )
    {
    errno = EINVAL;
    return( 0 );
    }
  return( result );
  } /* AtoS64 */


static int32_t ReadNumval( const char *numstr )
  /* ------------------------------------------------------------------------ **
   * Convert a numeric string into a 32-bit integer value.
   *
   *  Input:  numstr  - Pointer to a string to be translated into a numeric
   *                    value.
   *
   *  Output: A signed 32-bit integer.  This function returns 0 (zero) if
   *          anything goes wrong with the conversion, but zero (0) is also
   *          a valid result.  Check <errno> for errors.
   *
   *  Errors: If the function returns zero (0), the value of <errno> should
   *          be checked.  On success, <errno> will be zero.  On error,
   *          <errno> may have one of the following values:
   *            ERANGE  - The result is outside of the 32-bit signed integer
   *                      range.
   *            EINVAL  - Set if the input string did not begin with decimal
   *                      digits.
   *
   *  Notes:  - The conversion of the string is performed using the strtol(3)
   *            function, but the function then checks that the value is
   *            32-bits.  If the value read is less than INT32_MIN or greater
   *            than INT32_MAX then zero is returned and <errno> is set to
   *            ERANGE.
   *
   *            If the initial value is within the imposed 32-bit limit, then
   *            the trailing suffix character (if any) is read.  If it is a
   *            'k' or a 'K', the initial value is multiplied by 1K.  If it
   *            is an 'm' or an 'M', then the initial value is multipled by
   *            1M (1024 * 1024).
   *
   *            Once the conversion is done, the 32-bit range limit is
   *            re-tested.  Again, if the value is outside of the 32-bit
   *            range, zero is returned and <errno> is set to ERANGE.
   *
   *          - Since this uses strtol(3), it also behaves like strtol(3) in
   *            that the numeric conversion stops when a non-decimal
   *            character is encountered.
   *
   * ------------------------------------------------------------------------ **
   */
  {
  int64_t  result;
  char    *endptr;

  /* Perform the conversion, *and* set <endptr>.  */
  errno  = 0;
  result = (int64_t)strtol( numstr, &endptr, 10 );
  if( errno )
    return( 0 );

  /* First check. */
  if( (result < INT32_MIN) || (result > INT32_MAX) )
    {
    errno = ERANGE;
    return( 0 );
    }

  /* Deal with the suffix.  */
  switch( *endptr )
    {
    case 'K':
    case 'k':
      result *= 1024;
      break;
    case 'M':
    case 'm':
      result *= (1024 * 1024);
      break;
    }

  /* Second check. */
  if( (result < INT32_MIN) || (result > INT32_MAX) )
    {
    errno = ERANGE;
    return( 0 );
    }

  /* Return the result. */
  return( (int32_t)result );
  } /* ReadNumval */


static void DeriveUidGid( char *const usrnam, char *const grpnam )
  /* ------------------------------------------------------------------------ **
   * Parse and store the current and desired user & group IDs, if any.
   *
   *  Input:  usrnam  - A string containing either a username or a uid in
   *                    string format.  This string may also be in "a:b"
   *                    format, where a is the username/uid and b is the
   *                    groupname/gid.
   *          grpnam  - A string containing either a groupname or a gid in
   *                    string format.  If present, this overrides a
   *                    groupname/gid provided via the <usrnam> string.
   *
   *  Output: <none>
   *
   *  Effect: If the uid and/or gid can be correctly extracted from the
   *          input, and we can prove that we can set and reset the
   *          effective uid and gid, then the global variable <RunAs> will
   *          be set to point to the local static space known as <UidGid>.
   *          Otherwise, <RunAs> will be NULL.
   *
   *  Notes:  - The <usrnam> string maybe in <username>[:<groupname>]
   *            format.
   *          - If <grpnam> is given (not NULL), then it takes precedence
   *            over the groupname (if any) included in <usrnam>.
   *          - If no groupname is given using either of the above formats,
   *            then the primary group associated with <usrnam> is used.
   *
   * ------------------------------------------------------------------------ **
   */
  {
  static idMatrix UidGid[1];        /* Static space for the uid/gid.    */
  char           *tmpunam = NULL;   /* Will point to mallocated space.  */
  char           *tmpgnam = NULL;   /* Will point into another string.  */
  struct  passwd *pwent   = NULL;   /* Password File entry.             */
  struct  group  *grent   = NULL;   /* Group File entry.                */
  bool            pass2;            /* State of play.                   */
  int64_t         tmpInt64;         /* Scratch variable.                */

  /* Step 0:  Initialize a thing or two, and minimally validate the input.  */
  RunAs = NULL;
  if( (NULL == usrnam) && (NULL == grpnam) )
    return;

  /* Step 1a: Ensure we have a correctly parsed username/uid.
   *  Notes:
   *  - If tmpunam is not NULL when we finish, then it will point to memory
   *    that must be free()d.
   *  - If tmpgnam is not NULL when we finish, the it will point to a
   *    location within <usrnam> and must *not* be free()d.
   */
  if( NULL != usrnam )
    {
    size_t pos = strcspn( usrnam, ":" );

    if( NULL == (tmpunam = strndup( usrnam, pos )) )
      Fail( "Memory allocation failure in DeriveUidGid().\n" );
    if( ':' == usrnam[pos] )
      tmpgnam = &(usrnam[pos+1]);
    }
  /* Step 1b: How 'bout a correctly parsed groupname/gid?     */
  if( NULL != grpnam )
    tmpgnam = grpnam;

  /* Step 2a: Look up the user. */
  if( NULL != tmpunam )
    {
    errno = 0;
    pass2 = false;
    pwent = getpwnam( tmpunam );
    while( NULL == pwent )
      {
      /* According to the Linux getpwnam(3) manual page, POSIX is not
       * clear about the value of <errno> when an entry is not found.
       * This switch statement handles known errors, and ignores the
       * value of <errno> otherwise.
       */
      switch( errno )
        {
        case EINTR:   /* A signal was caught.                             */
        case EIO:     /* I/O error; Can't read /etc/group?  Unlikely.     */
        case EMFILE:  /* OPEN_MAX files already open.                     */
        case ENFILE:  /* Maximum files already open in the system.        */
        case ENOMEM:  /* Insufficient memory to allocate group structure. */
        case ERANGE:  /* To be returned by the getgrnam_r(3), etc.        */
          Fail( "Unable to look up username %s: %s.\n", tmpunam, StrErrno );
          break;
        default:  /* Not found. */
          {
          if( pass2 )
            Fail( "User <%s> not found.\n", tmpunam );
          pass2 = true;
          tmpInt64 = AtoS64( tmpunam );
          if( 0 != errno )
            Fail( "Unable to interpret user name %s: %s.\n",
                  tmpunam, StrErrno );
          pwent = getpwuid( (uid_t)tmpInt64 );
          break;
          }
        }
      }
    }

  /* Step 2b: Look up the group.  */
  if( NULL != tmpgnam )
    {
    errno = 0;
    pass2 = false;
    grent = getgrnam( tmpgnam );
    while( NULL == grent )
      {
      /* See notes above in step 2a.  */
      switch( errno )
        {
        case EINTR:   /* A signal was caught.                             */
        case EIO:     /* I/O error; Can't read /etc/group?  Unlikely.     */
        case EMFILE:  /* OPEN_MAX files already open.                     */
        case ENFILE:  /* Maximum files already open in the system.        */
        case ENOMEM:  /* Insufficient memory to allocate group structure. */
        case ERANGE:  /* To be returned by the getgrnam_r(3), etc.        */
          Fail( "Unable to look up group name %s: %s.\n", tmpgnam, StrErrno );
          break;
        default:  /* Not found. */
          {
          if( pass2 )
            Fail( "Group <%s> not found.\n", tmpgnam );
          pass2 = true;
          tmpInt64 = AtoS64( tmpgnam );
          if( 0 != errno )
            Fail( "Unable to interpret group name %s: %s.\n",
                  tmpgnam, StrErrno );
          grent = getgrgid( (uid_t)tmpInt64 );
          break;
          }
        }
      }
    }

  /* Step 3: We don't need <tmpunam> any more, so let's free the memory.  */
  if( NULL != tmpunam )
    free( tmpunam );

  /* Step 4: Initialize <UidGid> and extract new uid and gid. */
  UidGid->origUid = UidGid->safeUid = geteuid();
  UidGid->origGid = UidGid->safeGid = getegid();
  if( NULL != pwent )
    {
    UidGid->safeUid = pwent->pw_uid;
    UidGid->safeGid = pwent->pw_gid;
    }
  if( NULL != grent )
    UidGid->safeGid = grent->gr_gid;

  /* Step 5:  Test our values.  */
  if( setegid( UidGid->safeGid ) < 0 )
    Fail( "Cannot set group Id to %d; %s.\n", UidGid->safeGid, StrErrno );
  if( seteuid( UidGid->safeUid ) < 0 )
    Fail( "Cannot set user Id to %d; %s.\n", UidGid->safeUid, StrErrno );
  if( (seteuid( UidGid->origUid ) < 0) || (setegid( UidGid->origGid ) < 0) )
    Fail( "Cannot reset uid/gid; %s.\n", StrErrno );

  /* Step 6:  Let the world know. */
  RunAs = UidGid;

  /* One of three possible results:
   *  - If something seriously bad happened, we Fail()ed.
   *  - If we could not extract uid or gid, then <RunAs> is still NULL.
   *  - If everything worked okay, RunAs points to a semi-hidden static
   *    memory location that contains the uid and gid to which
   */
  } /* DeriveUidGid */

static void ReadOpts( int argc, char *argv[] )
  /* ------------------------------------------------------------------------ **
   * Read and process command line options.
   *
   *  Input:  argc  - you know what this is.
   *          argv  - you know what to do.
   *
   *  Output: <none>
   *
   * ------------------------------------------------------------------------ **
   */
  {
  int          i, c;
  extern char *optarg;
  extern int   optind;
  bool         TestRun     = false;
  bool         SpewVersion = false;
  bool         SpewHelp    = false;
  char        *UserName    = NULL;
  char        *GroupName   = NULL;

  while( (c = getopt( argc, argv, "d:fg:hm:op:tu:Vv" )) >= 0 )
    {
    switch( c )
      {
      case 'd':
       if( chdir( optarg ) < 0 )
         Fail( "Cannot change directory to %s; %s.\n",
               optarg, StrErrno );
       break;
      case 'f':
        BeDaemon = false;
        break;
      case 'g':
        GroupName = optarg;
        break;
      case 'h':
        SpewHelp = true;
        break;
      case 'm':
        MaxDump = (uint)ReadNumval( optarg );
        break;
      case 'o':
        Singular = true;
        break;
      case 'p':
        {
        int tmpport = GetTcpPortNo( optarg );

        if( tmpport < 1 )
          Fail( "Invalid port specified: %s.\n", optarg );
        Port = (uint16_t)tmpport;
        break;
        }
      case 't':
        TestRun = true;
        break;
      case 'u':
        UserName = optarg;
        break;
      case 'V':
        SpewVersion = true;
        break;
      case 'v':
        Verbosity++;
        break;
      default:
        Usage( argv[0], EXIT_FAILURE );
        break;
      }
    }

  /* If the user asked for version information, provide it now.
   */
  if( SpewVersion )
    {
    if( Verbosity > 0 )
      Err( "%s\n%s\n", Copyright, ID );
    else
      Err( "%s\n", Revision );
    }

  /* If help was requested, provide it and exit.
   */
  if( SpewHelp )
    Usage( argv[0], EXIT_SUCCESS );

  /* Collect the command to be executed.
   *   + Figure out how much space we need (including spaces and the NUL).
   *   + Allocate the string memory.
   *   + Copy the string chunks into the new space, adding spaces as needed.
   */
  for( c = 0, i = optind; i < argc; i++ )       /* How much space do we need? */
    c += (int)strlen( argv[i] ) + 1;
  if( 0 == c )                                  /* If no space needed then we */
    {                                           /* will exit.  If the Version */
    if( SpewVersion )                           /* was requested then bypass  */
      exit( EXIT_SUCCESS );                     /* an error message.          */
    Fail( "Missing command string; see help: %s -h\n", argv[0] );
    }

  CmdStr = (char *)malloc( (size_t)c );         /* Allocate the memory.       */
  if( NULL == CmdStr )
    Fail( "Cannot allocate string memory; %s.\n", StrErrno );

  for( *CmdStr = '\0', i = optind; i < argc; i++ )  /* Collect string chunks. */
    {
    if( i > optind )
      (void)strcat( CmdStr, " " );
    (void)strcat( CmdStr, argv[i] );
    }

  /* Collect UID/GID to run as.
   */
  DeriveUidGid( UserName, GroupName );

  /* If this is a test run, execute the command and exit.
   */
  if( TestRun )
    TestCmd();

  /* Provide detailed results.
   */
  if( Verbosity > 1 )
    {
    Err( "Info: The server will run in the %s, ",
         BeDaemon ? "background" : "foreground" );
    Err( "listening on port %d.\n", Port );
    }
  if( Verbosity > 2 )
    {
    Err( "      Maximum transfer: %d %sbyte%s.", MaxDump,
                0 == MaxDump ? "(unlimited) " : "",
                1 == MaxDump ? "" : "s" );
    Err( "%s\n", Singular ? "  Run once, then exit." : "" );
    if( NULL != RunAs )
      Err( "      Run as [%d:%d].\n", RunAs->safeUid, RunAs->safeGid );
    Err( "      [%s]\n", CmdStr );
    }

  } /* ReadOpts */


int main( int argc, char *argv[] )
  /* ------------------------------------------------------------------------ **
   * Program mainline.
   *
   *  Input:  argc  - You know what this is.
   *          argv  - You know what to do.
   *
   *  Output: EXIT_SUCCESS or EXIT_FAILURE, depending...
   *
   * ------------------------------------------------------------------------ **
   */
  {
  int lsock;    /* Listening socket. */

  ReadOpts( argc, argv );
  lsock = OpenSocket( INADDR_ANY );
  if( BeDaemon )
    Spawn();
  SetSignals();
  Serve( lsock );

  return( EXIT_SUCCESS );
  } /* main */

/* ========================================================================== */
