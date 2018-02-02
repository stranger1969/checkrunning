#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <dirent.h>
#include <signal.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <syslog.h>
#include <sys/param.h>
#include <errno.h>
#include <pwd.h>
#include <getopt.h>
#include <unistd.h>
#include <time.h>
#include "custconfig.h"

#define MAILPROG	"/usr/sbin/sendmail -i -t"
#define DEFAULT_INTERVAL	300
/* #define DEFAULT_MAIL	"checkrunning@ecommerce.com, tasks@monitor.ecommerce.com" */
#define DEFAULT_MAIL "tasks@monitor.ecommerce.com"
#define DEFAULT_CONFIG	"/etc/checkrunning.conf"

extern char *optarg;
extern int optind, opterr, optopt;

struct proc_s
{
		char procName[PATH_MAX+1];
		char execName[PATH_MAX+1];
		float upTime;
		int pid;
		char owner[9];
		int uid;
		char stat[2048];
		char statm[2048];
		char environ[2048];
		char cmdline[2048];
		char cwdPath[PATH_MAX+1];
};

long long startTimeSelf;
char *execExcludes[1024];
char *procExcludes[1024];
char *timeList[1024];
long *uidList;
int timeIntList[1024];
long unixtime;

int isDigitStr(char *str)
{
		if ( str == NULL )
				return 0;
		while ( *str != '\0' && isdigit(*str) ) str++;

		if ( *str == '\0' )
				return 1;

		return 0;
}

int getOwner(char *pid, struct proc_s *procStats)
{
		struct stat procDir;
		struct passwd *ownerStat;
		char name[MAXPATHLEN+1] = "/proc/";
		
		strncat(name, pid, MAXPATHLEN-6);
		
		// printf("Check process %s\n", pid);
		syslog(LOG_DEBUG, "Check process %s", pid);

		if ( stat(name, &procDir) == -1 )
		{
				if ( errno == ENOENT )
				{
						return(0);
				}

				syslog(LOG_ERR, "Can't access to process %s data (folder %s)", pid, name);
				return(0);
		}

		procStats->pid = atol(pid);
		procStats->uid = procDir.st_uid;

		if ( (ownerStat = getpwuid((uid_t)(procDir.st_uid))) == NULL )
		{
				syslog(LOG_ERR, "Can't get ownership for process %u (uid = %u)", pid, procDir.st_uid);
				return(0);
		}
		
		strncpy(procStats->owner, ownerStat->pw_name, sizeof(procStats->owner));

		return(1);
}

int usage()
{
	puts("checkrunning v 0.1b\n");
	puts("Usage:\n");
	puts("checkrunning [-c|--config path_to_config] [-d|--debug] [-i|--interval interval]\n");
	
	exit(1);
}

long long getStartTimeSelf()
{
		int fd;
		char stats[2048];
		char *tmp;
		char tmpbuf[2048];
		long long utime = 0;
		int i = 0;
		
		if ( (fd = open("/proc/self/stat", O_RDONLY)) == -1 )
		{
				syslog(LOG_ERR, "Can't open stats file for myself");
				return(0);
		}

		if ( read(fd, stats, sizeof(stats)-1) <= 0 )
		{
				close(fd);
				syslog(LOG_ERR, "Can't read stats file for myself");
				return(0);
		}
		close(fd);

		tmp = stats;		
		for (i = 0; i < 21 && tmp != NULL; i++)
		{
				if ( (tmp = strchr(tmp, ' ')) == NULL )
						return(0);
				tmp++;
		}

		strncpy(tmpbuf, tmp, sizeof(tmpbuf));
		
		if ( (tmp = strchr(tmpbuf, ' ')) == NULL)
		{
				syslog(LOG_ERR, "Error accured while parsing stats for myself");
				return(0);
		}
		*tmp = '\0';
	
		utime = atoll(tmpbuf);
		
		return(utime);
}

int getProcStats(struct proc_s *procStats)
{
		int fd;
		char buf[MAXPATHLEN+1];
		char path[MAXPATHLEN+1];
		char stats[2048];
		char *tmp;
		char tmpbuf[2048];
		long long stime = 0;
		long long utime = 0;
		int i = 0;

		bzero(buf, MAXPATHLEN+1);
		bzero(path, MAXPATHLEN+1);

		sprintf(buf, "/proc/%u/exe", procStats->pid);
		if ( readlink(buf, path,  MAXPATHLEN+1) < 0 )
		{
				syslog(LOG_ERR, "Can't read exepath for process %u", procStats->pid);
				return(0);
		}
		strcpy(procStats->procName, path);
		
		sprintf(buf, "/proc/%u/cwd", procStats->pid);
		if ( readlink(buf, path,  MAXPATHLEN+1) < 0 )
		{
				syslog(LOG_ERR, "Can't read exepath for process %u", procStats->pid);
				return(0);
		}
		strncpy(procStats->cwdPath, path, sizeof(procStats->cwdPath)+1);

		sprintf(buf, "/proc/%u/stat", procStats->pid);
		if ( (fd = open(buf, O_RDONLY)) == -1 )
		{
				syslog(LOG_ERR, "Can't open stats file for process %u", procStats->pid);
				return(0);
		}

		if ( read(fd, stats, sizeof(stats)-1) <= 0 )
		{
				close(fd);
				syslog(LOG_ERR, "Can't read stats file for process %u", procStats->pid);
				return(0);
		}
		close(fd);
		strcpy(procStats->stat, stats);
		
		sprintf(buf, "/proc/%u/statm", procStats->pid);
		if ( (fd = open(buf, O_RDONLY)) == -1 )
		{
				syslog(LOG_ERR, "Can't open stats file for process %u", procStats->pid);
				return(0);
		}

		if ( read(fd, procStats->statm, sizeof(procStats->statm)-1) <= 0 )
		{
				close(fd);
				syslog(LOG_ERR, "Can't read statm file for process %u", procStats->pid);
				return(0);
		}
		close(fd);

		sprintf(buf, "/proc/%u/environ", procStats->pid);
		if ( (fd = open(buf, O_RDONLY)) == -1 )
		{
				syslog(LOG_ERR, "Can't open stats file for process %u", procStats->pid);
				return(0);
		}

		if ( read(fd, procStats->environ, sizeof(procStats->environ)-1) <= 0 )
		{
				close(fd);
				syslog(LOG_ERR, "Can't read  file for process %u", procStats->pid);
				return(0);
		}
		close(fd);

		sprintf(buf, "/proc/%u/cmdline", procStats->pid);
		if ( (fd = open(buf, O_RDONLY)) == -1 )
		{
				syslog(LOG_ERR, "Can't open cmdline for process %u", procStats->pid);
				return(0);
		}

		if ( read(fd, procStats->cmdline, sizeof(procStats->cmdline)-1) <= 0 )
		{
				close(fd);
				syslog(LOG_ERR, "Can't read cmdline for process %u", procStats->pid);
				return(0);
		}
		close(fd);

		tmp = strchr(stats, ' ');
		if ( tmp == NULL )
		{
				syslog(LOG_ERR, "Error accured while parsing stats for process %u", procStats->pid);
				return(0);
		}
		tmp++;

		if ( *tmp == '(' ) tmp++;
		
		strncpy(procStats->execName, tmp, sizeof(procStats->execName));		
		tmp = strchr(procStats->execName, ')');
		if ( tmp != NULL ) *tmp = '\0';

		tmp = strchr(stats, ' ');
		for (i = 0; i < 21 && tmp != NULL; i++)
		{
				tmp = strchr(tmp, ' ');
				tmp++;
		}

		strncpy(tmpbuf, tmp, sizeof(tmpbuf));
		if ( (tmp = strchr(tmpbuf, ' ')) == NULL)
		{
				syslog(LOG_ERR, "Error accured while parsing stats for process %u", procStats->pid);
				return(0);
		}
		*tmp = '\0';

		stime = atoll(tmpbuf);
		tmp++;

		procStats->upTime = (startTimeSelf-stime)/100.;
		
		return(1);
}

int makeExcludesList()
{
		char buf[256];
		long i = 0;
		char *tmp = NULL;

		while(1)
		{
				sprintf(buf, "exec%i", i);
				if ( (tmp = get_value(buf)) == NULL )
						break;

				execExcludes[i] = strdup(tmp);
				sprintf(buf, "path%i", i);
				if ( (tmp = get_value(buf)) == NULL )
				{
						syslog(LOG_INFO, "Error in config: have no path for %s", execExcludes[i]);
						free(execExcludes[i]);
						continue;
				}
				
				procExcludes[i] = strdup(tmp);
				i++;
		}

		execExcludes[i] = NULL;
		procExcludes[i] = NULL;

		return(0);
}

int makeTimeList()
{
		char buf[256];
		long i = 0;
		char *tmp = NULL;

		while(1)
		{
			sprintf(buf, "time_path%i", i);
			if ( (tmp = get_value(buf)) == NULL )
					break;

			timeList[i] = strdup(tmp);
			sprintf(buf, "time_int%i", i);
			if ( (tmp = get_value(buf)) == NULL || atol(tmp) == 0 )
			{
					syslog(LOG_INFO, "Error in config: have no interval for %s", timeList[i]);
					free(timeList[i]);
					continue;
			}
			
			timeIntList[i] = atol(tmp);
			i++;
		}

		timeList[i] = NULL;
		timeIntList[i] = 0;

		return(0);
}

void freeUids()
{
	free(uidList);

	return;
}

int makeUIDList()
{
	long i = 0;
	long list_size = 0;
	char *value = NULL;
	char *tmp = NULL;
	char *tmp_v = NULL;

	if ( (value = get_value("UID")) == NULL )
		if ( (value = get_value("uid")) == NULL ) 
		{
			syslog(LOG_INFO, "no UIDs in list");
			uidList = malloc(sizeof(long));
			uidList[0] = 0;
			return(0);
		}

	tmp = strchr(value, ' ');
	if ( tmp == NULL )
		if ( atol(value) == 0 )
		{
			syslog(LOG_INFO, "no UIDs in list");
			return(0);
		}
	i = 1;

	if ( tmp != NULL )
		while((tmp = strchr(tmp, ' ')) != NULL)
		{
			i++;
			tmp++;
		}

	list_size = i+1;

	uidList = malloc(sizeof(long)*list_size);
	atexit(freeUids);

	tmp = value;
	for(i = 0; i < list_size-1; i++)
	{
		tmp_v = tmp;

		if ( tmp != NULL && (tmp = strchr(tmp, ' ')) != NULL )
			*tmp = '\0';

		uidList[i] = atol(tmp_v);
		tmp++;
	}

	uidList[list_size-1] = 0;
		
		i = 0;
		while(uidList[i] != 0)
		{
//				printf("Exclude uid: %d", uidList[i]);
			i++;
		}

	return(0);
}

int checkProcStats(struct proc_s *procStats)
{
		int i = 0;
		long interval = DEFAULT_INTERVAL;
		char *tmp;
		
		while(execExcludes[i] != NULL)
		{
				if ( !strcmp(procStats->execName, execExcludes[i])
						&& !strncmp(procStats->procName, procExcludes[i], strlen(procExcludes[i])) )
				{
						return(1);
				}

				i++;
		}

		if ( (tmp = get_value("interval")) != NULL && atol(tmp) != 0)
				interval = atol(tmp);

		i = 0;
		while(timeList[i] != NULL)
		{
				if ( !strcmp(procStats->procName, timeList[i]) )
				{
						if ( procStats->upTime <= timeIntList[i] )
						{
								syslog(LOG_DEBUG, "Process %u clean: %f", procStats->pid, procStats->upTime);
								// printf("Process %u clean: %f\n", procStats->pid, procStats->upTime);
								return(1);
						}
				}
				i++;
		}
		
		i = 0;
		while(uidList[i] != 0)
		{
			if (procStats->uid == uidList[i])
			{
				syslog(LOG_INFO, "Found long running process %d of user %d", procStats->pid, uidList[i]);
				return(1);
			}

			i++;
		}
								

		if ( procStats->upTime <= interval )
		{
				syslog(LOG_DEBUG, "Process %u clean: %f", procStats->pid, procStats->upTime);
				// printf("Process %u clean: %f\n", procStats->pid, procStats->upTime);
				return(1);
		}

		syslog(LOG_DEBUG, "Process %u is overruning: uptime %f, owner %s, exec %s, path %s", procStats->pid,
						procStats->upTime, procStats->owner, procStats->execName, procStats->procName);
		// printf("Process %u is overruning: uptime %f, owner %s, exec %s, path %s\n", procStats->pid,
		//				procStats->upTime, procStats->owner, procStats->execName, procStats->procName);
		return(0);
}

int sendInfo(struct proc_s *procStats)
{
		FILE *cmd;
		char buf[2048];
		char *tmp;

/*
		char host_name[64];

		gethostname(host_name, sizeof(host_name)-1);

		if ( (cmd = popen(MAILPROG, "w")) == NULL )
		{
				syslog(LOG_ERR, "Can't send mail: %m");
				return(0);
		}

		fputs("From: root\n", cmd);
		fputs("To: ", cmd);
		if ( (tmp = get_value("email")) != NULL )
				fputs(tmp, cmd);
		else
				fputs(DEFAULT_MAIL, cmd);

		fputs("\n", cmd);
		fputs("Subject: ", cmd);
		fputs(host_name, cmd);
		fputs(": task terminated!\n\n", cmd);
		fputs("HOST ", cmd);
		fputs(host_name, cmd);
		sprintf(buf, "\nTIME %u\n", unixtime);
		fputs(buf, cmd);
		sprintf(buf, "PID %u\nOWNER %s\nEXEC %s\nPROC %s\nUPTIME %f\n", procStats->pid, procStats->owner, procStats->execName, procStats->procName, procStats->upTime);
		fputs(buf, cmd);
		fputs("CMD ", cmd);
		fputs(procStats->cmdline, cmd);
		fputs("\n", cmd);
		sprintf(buf, "CWD %s\n", procStats->cwdPath);
		fputs(buf, cmd);
		fputs("ENV: ", cmd);
		fputs(procStats->environ, cmd);
		fputs("\n\n", cmd);
		fputs("Stat:\n<<\n", cmd);
		fputs(procStats->stat, cmd);
		fputs("\n>>\n", cmd);
		fputs("Statm:\n<<\n", cmd);
		fputs(procStats->statm, cmd);
		fputs("\n>>\n", cmd);
		fputs(".\n", cmd);

		pclose(cmd);
*/		
		syslog(LOG_INFO, "Killed proccess %d (uid %d owner %s, exec %s, cmd %s, cwd %s)", procStats->uid, procStats->pid, procStats->owner, procStats->execName, procStats->cmdline, procStats->cwdPath);
		return(0);
}

int killTheBeast(struct proc_s *procStats)
{
		int kill_signal = 9;
		char *tmp = NULL;

		if ( (tmp = get_value("kill_signal")) != NULL && atol(tmp) != 0 )
				kill_signal = atol(tmp);

		kill(procStats->pid, kill_signal);

		return(0);
}

int CheckProcess(char *pid)
{
		char *owner;
		struct proc_s procStats;
		long i;


		if ( !getOwner(pid, &procStats) )
		{
				return(0); /* process not exist - done? */
		}

		if ( procStats.uid < 300 )
		{
				return(0); /* root processes, don't touch */
		}
	
		i = 0;
		while(uidList[i] != 0)
		{
			if (procStats.uid == uidList[i])
			{
				syslog(LOG_INFO, "Found long running process %d of user %d", procStats.pid, uidList[i]);
				return(0);
			}

			i++;
		}

		if ( !getProcStats(&procStats) )
		{
				return(0); /* process not exist - done? */
		}

		if ( !checkProcStats(&procStats) )
		{
				sendInfo(&procStats);
				killTheBeast(&procStats);
		}

		return(0);
}

int main(int argc, char **argv)
{
		DIR *procdir;
		struct dirent *currentry;
		int opt_index = 0;
		int debug_level = 0;
		int interval = 0;
		int c;
		char *config_path = NULL;
		static struct option long_opts[] =
		{
			{"config", 1, 0, 0},
			{"debug", 1, 0, 0},
			{"interval", 1, 0, 0},
			{0, 0, 0, 0}
		};
		startTimeSelf = 0;
		debug_level = LOG_UPTO(LOG_INFO);

	while ( (c = getopt_long(argc, argv, "c:di:", long_opts, &opt_index)) != -1 )
	{
		switch(c)
		{
			case 0:
				if ( !strcmp(long_opts[opt_index].name, "config") )
				{
						config_path = strdup(optarg);
						break;
				}
				
				if ( !strcmp(long_opts[opt_index].name, "debug") )
				{
						debug_level = LOG_UPTO(LOG_DEBUG);
						break;
				}

				if ( !strcmp(long_opts[opt_index].name, "interval") )
				{
						interval = atol(optarg);
						break;
				}

			case 'c':
				config_path = strdup(optarg);
				break;

			case 'd':
				debug_level = LOG_UPTO(LOG_DEBUG);
				break;

			case 'i':
				interval = atol(optarg);
				break;

			default:
				usage();
				break;
		}
	}

		openlog("checkrunning", LOG_PID|LOG_CONS, LOG_LOCAL4);
		setlogmask(debug_level);

		syslog(LOG_INFO, "Start checking");
		// printf("Start check. Log level: %i (%i)\n", debug_level, LOG_DEBUG);

		if ( config_path == NULL )
				config_path = strdup(DEFAULT_CONFIG);
		
		if ( init_conf(config_path) == -1 )
		{
				closelog();
				return(-1);
		}
		
		startTimeSelf = getStartTimeSelf();
		unixtime = time(NULL);
		makeExcludesList();
		makeTimeList();
		makeUIDList();


		if ( (procdir = opendir("/proc")) == NULL )
		{
				syslog(LOG_ERR, "Can't open /proc for reading");
				closelog();
				exit(-1);
		}

		while ( (currentry = readdir(procdir)) != NULL )
		{
				if ( *(currentry->d_name) == '.')
						continue;

				syslog(LOG_DEBUG, "Check entry: %s", currentry->d_name);
				// printf("Check entry: %s\n", currentry->d_name);

				if ( isDigitStr(currentry->d_name) )
						CheckProcess(currentry->d_name);
		}

		closedir(procdir);
		
		closelog();
		return(0);
}
