/* ========================================================================== **
 *                                badfingerd.c
 *
 * Copyright:
 *  Copyright (C) 2010 by Christopher R. Hertel
 *
 * Email: crh@ubiqx.mn.org
 *
 * $Id: badfingerd.c 5 2014-12-17 05:20:23Z crh $
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
 *  program ignores the incoming request entirely.  Instead, it runs a
 *  pre-specified shell command and redirects the output back over the TCP
 *  connection.  When EOF is reached, or when the specified maximum number
 *  of bytes has been returned to the caller, the TCP connection is closed.
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
 *  - This program is currently quite rudimentary.  For completeness:
 *
 *    + There should be a /var/run/badfingerd.pid file if we run as
 *      root on the default port.  (/var/run/badfingerd-<port>.pid
 *      otherwise?)
 *
 *    + It should be possible to run the command in the context of a
 *      specified user.  That is, start as root (since we may need to
 *      listen on a privileged port) but then downgrade to a different
 *      user context (e.g., nobody.nogroup).  In fact, nobody.nogroup
 *      should be the default, overridden from the command line.  By
 *      default, assign the group as follows:
 *      - Check for the existence of 'nogroup'.  If it doesn't exist,
 *      - check for the existence of the 'nobody' group.  If it doesn't
 *        exist, throw an error.  Same for the "nobody" user.
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
 *    + We should be able to handlie IPv4 and/or IPv6.
 *
 *    + There should be a management interface of some sort.  At minimum,
 *      the daemon should exit gracefully if it receives a SIGHUP or
 *      SIGTERM.  Statistics collection and logging would also be useful.
 *
 *    + It would be interesting if badfingerd were multi-threaded.
 *      One thread per TCP connection, with an enforced maximum number of
 *      threads.  Perhaps with a thread pool.
 *
 *    + Some versions of finger restrict the number of characters of
 *      received data that are displayed.  One work-around is to use
 *      netcat (nc) or telnet instead:
 *        $ nc <remote host> 79
 *        $ telnet <remote host> 79
 *
 * ========================================================================== **
 */

#include <stdio.h>      /* Standard I/O stuff.              */
#include <stdlib.h>     /* For EXIT_SUCCESS, etc.           */
#include <stdint.h>     /* Extended integer types.          */
#include <stdbool.h>    /* Standard boolean type.           */
#include <unistd.h>     /* For getopt(3).                   */
#include <errno.h>      /* The errno variable.              */
#include <string.h>     /* For strerror(3), strcat(3), etc. */
#include <stdarg.h>     /* Variable argument lists.         */

#include <signal.h>     /* For sigaction(2).                */
#include <netinet/in.h> /* Network address structures.      */
#include <arpa/inet.h>  /* Needed by inet_ntoa(3).          */
#include <sys/socket.h> /* For listen(2) and accept(2).     */
#include <netdb.h>      /* For getservbyname(3).            */

/* -------------------------------------------------------------------------- **
 * Macros:
 *
 *  Err() - This is a conceited little macro that simply replaces
 *          fprintf( stderr, ... ) with something shorter and easier
 *          to type.
 */

#define Err( ... ) (void)fprintf( stderr, __VA_ARGS__ )


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
                = "$Id: badfingerd.c 5 2014-12-17 05:20:23Z crh $";

static const char *HelpMsg[] =
  {
  "  Available Options:",
  "  -d <dir>   Change directory to <dir>.",
  "  -f         Run in the foreground, not as a daemon.",
  "  -h         Produce this useful help message, then exit.",
  "  -m <max>   Maximum number of bytes to return.  Default = 0"
  " (unlimited).",
  "  -o         Run once; exit after one connection.",
  "  -p <port>  Listen on the specified port number.  Default = 79.",
  "  -t         Test:  Execute the command in the foreground, then exit.",
  "  -V         Output version information.",
  "  -v         Be verbose.  Add more -v's for more verbosity.",
  NULL
  };


/* -------------------------------------------------------------------------- **
 * Global Variables:
 *
 */

static bool     BeDaemon  = true;
static uint32_t MaxDump   = 0;
static bool     Singular  = false;
static uint16_t Port      = 79;
static int      Verbosity = 0;
static char    *CmdStr    = NULL;


/* -------------------------------------------------------------------------- **
 * Static Functions:
 */

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
  ssize_t count;
  size_t  outcount;

  do
    {
    newsock = accept( sock, NULL, NULL );       /* Answer the call.        */
    subStream = popen( CmdStr, "re" );          /* Capture command output. */

    /* While there is either no limit, or until we reach the limit...
     */
    outcount = 0;
    while( (0 == MaxDump) || (outcount < MaxDump) )
      {
      count     = fread( bufr, 1, bSIZE, subStream );
      outcount += count;

      /* If there is a limit to the number of bytes requested,
       * enforce that limit.  Make sure the message sent ends
       * with a newline.
       */
      if( (MaxDump > 0) && (outcount >= MaxDump) )
        {
        count -= (outcount - MaxDump);
        bufr[count - 1] = '\n';
        }
      count = write( newsock, bufr, count );

      /* If we read, or sent, less than bSIZE bytes this go-round,
       * then we have either reached EOF or the maximum output
       * limit (MaxDump).  It is also possible that write(2) returned
       * an error value (-1).  In any of those cases, we're done.
       */
      if( count < bSIZE )
        break;
      }

    pclose( subStream );
    close( newsock );
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
  }


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
    Fail( "Cannot spawn child process; %s\n", strerror( errno ) );
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
    Fail( "Cannot create IPv4 TCP socket; %s\n", strerror( errno ) );
  if( setsockopt( sock, SOL_SOCKET, SO_REUSEADDR, yes, sizeof(int) ) < 0 )
    Fail( "Setting socket option SO_REUSEADDR; %s.\n", strerror( errno ) );

  /* Bind the socket to the interface. */
  v4_addr.sin_family      = AF_INET;
  v4_addr.sin_port        = htons( Port );
  v4_addr.sin_addr.s_addr = if_addr;
  result = sizeof( struct sockaddr_in );
  result = bind( sock, (struct sockaddr *)(&v4_addr), result );
  if( result < 0 )
    Fail( "Cannot bind IPv4 socket to address %s, port %d; %s\n",
          inet_ntoa( v4_addr.sin_addr ), Port, strerror( errno ) );

  /* Set the socket to listen for connections (passive--as opposed
   * to making a connection, which is active).
   */
  backlog = ( Singular ) ? 1 : 12;
  if( listen( sock, backlog ) < 0 )
    Fail( "Cannot listen on port %d; %s.\n", Port, strerror( errno ) );

  return( sock );
  } /* OpenSocket */


int GetTcpPortNo( const char *pname )
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

  subStream = popen( CmdStr, "re" );          /* Capture command output. */

  while( (0 == MaxDump) || (outcount < MaxDump) )
    {
    count     = fread( bufr, 1, bSIZE, subStream );
    outcount += count;

    /* If there is a limit to the number of bytes requested,
     * enforce that limit.  Make sure the message sent ends
     * with a newline.
     */
    if( (MaxDump > 0) && (outcount >= MaxDump) )
      {
      count -= (outcount - MaxDump);
      bufr[count - 1] = '\n';
      }
    count = write( STDOUT_FILENO, bufr, count );

    /* If we read, or sent, less than bSIZE bytes this go-round,
     * then we have either reached EOF or the maximum output
     * limit (MaxDump).  In either case, we're done.
     */
    if( count < bSIZE )
      break;
    }

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


static int32_t ReadNumval( const char *numstr )
  /* ------------------------------------------------------------------------ **
   * Convert a numeric string into an integer value.
   *
   *  Input:  numstr  - Pointer to a string to be translated into a numeric
   *                    value.
   *
   *  Output: A signed 32-bit integer.  This function returns 0 (zero) if
   *          anything goes wrong with the conversion.
   *
   *  Notes:  The conversion of the string is performed using the strtol(3)
   *          function, but the function then limits the initial value to
   *          32-bits.  If the value read is less than INT32_MIN or greater
   *          than INT32_MAX then zero is returned.
   *
   *          If the initial value is within the imposed 32-bit limit, then
   *          the trailing suffix character (if any) is read.  If it is an
   *          'k' or a 'K', the initial value is multiplied by 1K.  If it
   *          is an 'm' or an 'M', then the initial value is multipled by
   *          1M (1024 * 1024).
   *
   *          Once the conversion is done, the 32-bit range limit is
   *          re-tested.  Again, if the value is outside of the 32-bit
   *          range, zero is returned.
   *
   * ------------------------------------------------------------------------ **
   */
  {
  int64_t  result;
  char    *endptr;

  errno  = 0;
  result = (int64_t)strtol( numstr, &endptr, 10 );
  if( errno )
    return( 0 );

  if( (result < INT32_MIN) || (result > INT32_MAX) )
    return( 0 );

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

  if( (result < INT32_MIN) || (result > INT32_MAX) )
    return( 0 );

  return( (uint32_t)result );
  } /* ReadNumval */


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

  while( (c = getopt( argc, argv, "d:fhm:op:tVv" )) >= 0 )
    {
    switch( c )
      {
      case 'd':
       if( chdir( optarg ) < 0 )
         Fail( "Cannot change directory to %s; %s.\n",
               optarg, strerror( errno ) );
       break;
      case 'f':
        BeDaemon = false;
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
        Port = tmpport;
        break;
        }
      case 't':
        TestRun = true;
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
    c += strlen( argv[i] ) + 1;
  if( 0 == c )                                  /* If no space needed then we */
    {                                           /* will exit.  If the Version */
    if( SpewVersion )                           /* was requested then bypass  */
      exit( EXIT_SUCCESS );                     /* an error message.          */
    Fail( "Missing command string; see help: %s -h\n", argv[0] );
    }

  CmdStr = (char *)malloc( (size_t)c );         /* Allocate the memory.       */
  if( NULL == CmdStr )
    Fail( "Cannot allocate string memory; %s.\n", strerror( errno ) );

  for( *CmdStr = '\0', i = optind; i < argc; i++ )  /* Collect string chunks. */
    {
    if( i > optind )
      (void)strcat( CmdStr, " " );
    (void)strcat( CmdStr, argv[i] );
    }

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
