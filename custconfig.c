#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>
#include <string.h>

#define CONFIG "/etc/checkrunning.conf"

struct s_config_vars
{
		char *name;
		char *value;
} config_vars[1024];

static long config_length;

int parse_line(char *line)
{
		char *tmp;
		char *src = line;

//		printf("Config line: %s\n", line);
		if ( (tmp = strchr(line, '\n')) != NULL )
				*tmp = '\0';

		tmp = line;
		
		while ( *tmp == ' ' || *tmp == '\t' && *tmp != '\0' )
				tmp++;

//		printf("tmp0: %s\n", tmp);
		if ( *tmp == '\0' )
				return(1);

		src = tmp;

		tmp = strchr(src, '=');
		tmp--;
		while ( tmp != src && (*tmp == ' ' || *tmp == '\t') )
				tmp--;
		
		tmp++;
		*tmp = '\0';

		if ( strlen(src) == 0 )
				return(-1);

//		printf("src: %s\n", src);
		config_vars[config_length].name = strdup(src);
		
		tmp++;
		
//		printf("tmp: %s\n", src);

		while ( *tmp == ' ' || *tmp == '\t' || *tmp == '=' && *tmp != '\0' )
				tmp++;
		src = tmp;
		
//		printf("src2: %s\n", src);

		tmp = strchr(src, '\0');
		tmp--;
		while ( tmp != src && *tmp == ' ' || *tmp == '\t' )
				tmp--;
		
		tmp++;
		*tmp = '\0';
		if ( strlen(src) == 0 )
		{
				config_vars[config_length].value = NULL;
				return(0);
		}

		config_vars[config_length].value = strdup(src);

		return(0);
}

void free_config()
{
		int i = 0;
		while(config_vars[i].name != NULL)
		{
				if ( config_vars[i].name )
						free(config_vars[i].name);
				if ( config_vars[i].value )
						free(config_vars[i].value);

				i++;
		}
}

int parse_conf(FILE *conf)
{
		char buf[2048];
		int stat = 0;
		char *tmp;
		config_length = 0;
		int i = 0;

		while( (tmp = fgets(buf, sizeof(buf)-1, conf)) != NULL )
		{
//			printf("Line: %s\n", buf);
			if ( (stat = parse_line(buf)) == -1 )
			{
				syslog(LOG_ERR, "Error accured in line '%s'", buf);
//				printf("Error accured in line '%s'", buf);
			}
			else
			{
				if ( stat == 0 )
				{
//			printf("Name: %s, Value:%s\n", config_vars[config_length].name, config_vars[config_length].value);
					config_length++;
				}
			}
		}
		
		config_vars[config_length].name = NULL;
		config_vars[config_length].value = NULL;

		for(i = 0; i < config_length; i++)
		{
//			printf("Conf name: %s, conf value: %s\n", config_vars[i].name, config_vars[i].value);
		}
		
		atexit(free_config);
		
		return(0);
}

int init_conf(char *path)
{
		char * config_path;
		FILE *conf;
		
		if ( path == NULL )
				config_path = CONFIG;
		else
				config_path = path;


		if ( (conf = fopen(config_path, "r")) == NULL )
		{
				syslog(LOG_ERR, "Can't read config");
				return(-1);
		}

		if ( parse_conf(conf) == -1 )
		{
				syslog(LOG_ERR, "Error accured while parsing confing");
				return(-1);
		}

		return(0);
}

char *get_value(char *confname)
{
	struct s_config_vars *tmp_conf = config_vars;

	while ( tmp_conf->name != NULL )
	{
			if ( !strcmp(tmp_conf->name, confname) )
					return(tmp_conf->value);
			tmp_conf++;
	}

	return(NULL);
}
