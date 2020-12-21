#include "headers.h"
#include "logger.h"
#include "dumper.h"

int
main(int argc, char *argv[])
{
    int ret_value;
    int c;
    unsigned long pid;
    uid_t uid;

    if (argc < 2)
    {
        printf("usage: %s [-d/-e/-p]\n", argv[0]);
        printf("\t-d: show debug lines.\n");
        printf("\t-e: show error lines.\n");
        printf("\t-p: pid of process to dump\n");
        printf("Badly written by: Fare9\n");
        printf("\n\n");
        exit(0);
    }

    while ((c = getopt(argc, argv, "dep:")) != -1)
	{
        switch (c)
        {
        case 'd':
            set_debug_flag();
            break;
        case 'e':
            set_error_flag();
            break;
        case 'p':
            pid = (pid_t)strtoul(optarg, NULL, 10);
            if (pid == ULONG_MAX && errno == ERANGE)
            {
                printf("Error non valid pid.\n");
                exit(-1);
            }
            break;
        default:
            break;
        }
    }

    if ((uid = geteuid()) != 0)
    {
        printf("You must execute the dumper as root in order to attach to process\n");
        exit(0);
    }
    
    ret_value = dump_process((pid_t)pid);

    if (ret_value == -1)
    {
        perror("ERROR ANALYZING FILE");
        exit(-1);
    }
    else if (ret_value == -2)
    {
        fprintf(stderr, "Uncategorized error analyzing file\n");
        exit(-2);
    }
    

    return 0;
}