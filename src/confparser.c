/****************************************************************************
 *                                                                          *
 *  confparser.c - A parser for the configuration files of crdss servers.   *
 *                                                                          *
 *                    Copyright (c) 2019 Till Miemietz                      *
 *                                                                          *
 ****************************************************************************/


/****************************************************************************
 *                                                                          *
 *                           include statements                             *
 *                                                                          *
 ****************************************************************************/


#include <stdio.h>                       /* output error messages           */
#include <stdlib.h>                      /* memory allocation, ...          */
#include <unistd.h>                      /* standard UNIX calls like access */
#include <string.h>                      /* string manipulation             */
#include <arpa/inet.h>                   /* converting IP addrs to strings  */

#include "include/confparser.h"          /* declaration of config parser    */
#include "include/slist.h"               /* header for slist implementation */
#include "include/utils.h"               /* for setting log levels          */
#include "include/cap.h"                 /* crdss capabilities              */

/****************************************************************************
 *                                                                          *
 *                           type definitions                               *
 *                                                                          *
 ****************************************************************************/

 
/* file-local raw parsing structures that are independent of parser caller  */

/* contains a config element, i.e. a part of the file that is opened by a   *
 * heading of the form [<elem name>]                                        */
struct config_elem {
    char         *elem_name;
    struct slist *attributes;   /* shall contain a slist with config_attr   */
};

struct config_attr {
    char         *key;
    struct slist *values;       /* shall contain at least one string        */
};

/****************************************************************************
 *                                                                          *
 *                          static helper functions                         *
 *                                                                          *
 ****************************************************************************/


/****************************************************************************
 *
 * Frees all dynamically allocated elements that are created during a call to
 * parse_raw. This function must only be called on results of that routine, 
 * otherwise the behavior is undefined. 
 *
 * Params: parse_tree - A pointer to a element tree created by parse_raw.
 */
static void free_raw(struct slist *parse_tree) {
    while(parse_tree != NULL) {
        struct config_elem *elem = (struct config_elem *) parse_tree->data;

        while (elem->attributes != NULL) {
            struct config_attr *attr = 
                (struct config_attr *) elem->attributes->data;

            while (attr->values != NULL) {
                free(attr->values->data);
                attr->values = slist_remove(attr->values, attr->values->data);
            }

            free(attr->key);
            elem->attributes = slist_remove(elem->attributes, attr);
        }

        free(elem->elem_name);
        parse_tree = slist_remove(parse_tree, elem);
    }
}

/****************************************************************************
 *
 * Performs parsing of the configuration file located in confpath. The caller
 * must ensure that this file is readable. Note that this function does 
 * syntax checking only, semantic correctness of the config file shall be 
 * examined by the caller. This function will allocate a list of config_elem
 * structs that contain a list of config_attrs that in turn contain a list
 * of value strings. Upon successful execution, a pointer to these in-memory
 * representation of the config file will be returned in elems. The caller is
 * responsible for freeing the memory referenced by elems after use.
 *
 * Params: confpath - path to the configuration file being parsed.
 *         elems    - pointer to a resulting in-memory representation of the
 *                    config file.
 *
 * Returns: 0 in case of success, a non-zero integer on error
 */
static int parse_raw(char *confpath, struct slist **elems) {
    struct slist *elements = NULL;  /* new tree to construct                */
    FILE         *conf_file;
    int           line_nr = 1;      /* current location of parser           */
    int           exp_ass = 0;      /* assignment expected next             */
    int           tk_val  = 0;      /* 1 if following tokens are values     */

    char    *line = NULL;           /* next line to read                    */
    size_t   rlen = 0;              /* special getline parameter            */
    ssize_t   len;                  /* length of next line                  */

    /* field for calls to strtok_r */
    char *token;
    char *pos;

    struct config_elem *c_elm;      /* look up parts of the tree            */

    if ((conf_file = fopen(confpath, "r")) == NULL) {
        fprintf(stderr, "Unable to open logfile.\n");
        return(1);
    }

    while ((len = getline(&line, &rlen, conf_file)) != -1) {
        /* skip blank lines */
        if (strcmp(line, "\n") == 0) 
            goto nextline;

        /* initialize token search with line argument, then iterate through  *
         * the line using the posision marker pos                            */
        for (token = strtok_r(line, " ", &pos); token != NULL;
             token = strtok_r(NULL, " ", &pos)) {
            
            /* skip empty tokens */
            if (strlen(token) == 0 || strcmp(token, "\n") == 0)
                continue;
            
            /* cut of trailing newline characters */
            if (token[strlen(token) - 1] == '\n')
                token[strlen(token) - 1] = '\0';

            /* fprintf(stderr, "parsing token \"%s\"\n", token); */
            /* check for comments */
            if (strncmp(token, "#", 1) == 0)
                goto nextline;

            /* check if new config elem was started (surrounded by brackets)*/
            if (strncmp(token, "[", 1) == 0 && 
                strncmp(token + strlen(token) - 1, "]", 1) == 0 &&
                ! exp_ass) {
                struct config_elem *elm = calloc(1, sizeof(struct config_elem));
              
                fprintf(stderr, "Beginning new config elem %s\n", token);

                if (elm == NULL)
                    goto error_mem;

                elm->elem_name = calloc(strlen(token) - 1, sizeof(char));
                if (elm->elem_name == NULL)
                    goto error_mem;

                memcpy(elm->elem_name, token + 1, strlen(token) - 2);
                if (slist_insert(&elements, elm) != 0)
                    goto error_mem;

                /* nothing must be on the line after element declaration */
                break;
            }

            /* after checks above, line must be attribute assignment, hence *
             * there is at least one config_elem in the parse tree          */
            if (elements == NULL) {
                fprintf(stderr, "Line %d: Unexpected attribute assignment "
                        "outside element scope.\n", line_nr);
                goto error;
            }
            
            /* an attribute name must be followed by a = to separate names  *
             * from attribute values                                        */
            if (exp_ass) {
                if (strncmp(token, "=", 1) == 0) {
                    /* mandatory character '=' was seen */
                    exp_ass = 0;
                    continue;
                }
                else {
                    fprintf(stderr, "Line %d: Expected assignment after "
                            "attribute name.\n", line_nr);
                    goto error;
                }
            }
            
            c_elm = (struct config_elem *) elements->data;
            
            if (tk_val == 0) {
                /* read attribute name */
                struct config_attr *attr = calloc(1,sizeof(struct config_attr));
                if (attr == NULL)
                    goto error_mem;

                attr->key = calloc(strlen(token) + 1, sizeof(char));
                if (attr->key == NULL)
                    goto error_mem;

                memcpy(attr->key, token, strlen(token));
                attr->key[strlen(token)] = '\0';

                if (slist_insert(&c_elm->attributes, attr) != 0)
                    goto error_mem;
                exp_ass = 1;
                tk_val  = 1;
            }
            else {
                /* read attribute value */
                struct config_attr *attr = 
                    (struct config_attr *) c_elm->attributes->data;
                char *value = calloc(strlen(token) + 1, sizeof(char));
                
                if (value == NULL)
                    goto error_mem;
                memcpy(value, token, strlen(token));
                
                if (slist_insert(&attr->values, value) != 0)
                    goto error_mem;
            }
        }

nextline:
        exp_ass = 0;    /* no multi-line attribute assignments              */
        tk_val  = 0;    /* new line will start with new attribute name      */
        line_nr++;
    }

    /* everything is ok w.r.t. syntax, set return pointer and exit          */
    *elems = elements;
    free(line);
    return(0);

error_mem:
    fprintf(stderr, "Error while allocating memory for parsing structure.\n");
error:
    free_raw(elements);
    free(line);
    return(1);
}

/***************************************************************************
 *
 * Translate a string as given in the configuration files into a loglevel
 * defined in "include/utils.h". If the string does not match any loglevel,
 * the default level (WARN) will be returned.
 *
 * Params: lvlstr - string encoding the log level.
 *
 * Returns: A log level integer as declared in "include/utils.h"
 */
static int lstrtoi(char *lvlstr) {
    if (strcmp(lvlstr, "severe") == 0) {
        return(SEVERE);
    }
    else if (strcmp(lvlstr, "error") == 0) {
        return(ERROR);
    }
    else if (strcmp(lvlstr, "warn") == 0) {
        return(WARN);
    }
    else if (strcmp(lvlstr, "info") == 0) {
        return(INFO);
    }
    else if (strcmp(lvlstr, "debug") == 0) {
        return(DEBUG);
    }
    else { 
        fprintf(stderr, "Unknown log level %s, switching to "
                "default (WARN).\n", lvlstr);
        return(WARN);
    }
}

/***************************************************************************
 *
 * Translate a list of permission strings into a uint16_t representation as
 * defined in cap.h.
 *
 * Params: str_list - list of permission strings.
 *
 * Returns: The permissions described inside the list encoded in a uint16_t.
 */
static uint16_t permstrtoi(struct slist *str_list) {
    char *perm_str;             /* a single permission string in the list   */

    uint16_t res = 0;           /* no permissions by default                */

    for (; str_list != NULL; str_list = str_list->next) {
        perm_str = (char *) str_list->data;

        if (strcmp(perm_str, "read") == 0 || strcmp(perm_str, "r") == 0) {
            res = res | CAP_READ;
        }
        else if (strcmp(perm_str, "write") == 0 || strcmp(perm_str, "w") == 0) {
            res = res | CAP_WRITE;
        }
        else if (strcmp(perm_str, "trim") == 0 || strcmp(perm_str, "t") == 0) {
            res = res | CAP_TRIM;
        }
        else {
            fprintf(stderr, "Unknown permission string \"%s\" found.\n", 
                    perm_str);
        }
    }

    return(res);
}

/****************************************************************************
 *                                                                          *
 *                          function implementation                         *
 *                                                                          *
 ****************************************************************************/


/***                  functions defined in confparser.h                   ***/

/* Parses the server configuration file located at path confpath            */
int parse_server_config(char *confpath, struct server_config *sconf) {
    struct slist *conf_elems;
    struct slist *ptr;
    
    int srv_flag = 0;           /* 1 if server section was defined          */
    int snc_flag = 0;           /* 1 if at least one SNIC section was def'd */
    
    /* check if config file exists and is readable                          */
    if (access(confpath, R_OK)) {
        fprintf(stderr, "Failed to read config file %s.\n", confpath);
        return(1);
    }

    /* firstly, do raw parsing of config file                               */
    if (parse_raw(confpath, &conf_elems) != 0) {
        fprintf(stderr, "Syntax error while parsing config file %s\n", 
                confpath);
        return(2);
    }

    /* syntax in config file was ok, now check for completeness             */
    ptr = conf_elems;
    while (ptr != NULL) {
        struct config_elem *elm = (struct config_elem *) ptr->data;
        
        /*
        fprintf(stderr, "Elem name: \"%s\"\n", elm->elem_name);
        fprintf(stderr, "No. of attributes: %u\n", 
                slist_length(elm->attributes));
        */
        
        /* check for possible configuration elements */
        if (strcmp(elm->elem_name, "SERVER") == 0) {
            /* a SERVER config element must have attributes "addr" (IP),    *
             * port and devices. It may have a setting for the log level    */
            /* fprintf(stderr, "Starting processing of SERVER element.\n"); */

            if (srv_flag == 1) {
                fprintf(stderr, "Duplicate declaration of SERVER config "
                        "element\n");
                goto err;
            }

            struct slist *attr_list = elm->attributes;    /* attribute list */
            while (attr_list != NULL) {
                struct config_attr *attr = 
                    (struct config_attr *) attr_list->data;
                
                /* fprintf(stderr, "Processing attr %s\n", attr->key); */
                /* switch between different attribute names                 */
                if (strcmp(attr->key, "addr") == 0) {
                    char *ip = (char *) attr->values->data;
                    if (inet_pton(AF_INET, ip, &sconf->addr.sin_addr) != 1) {
                        fprintf(stderr, "String %s is not a valid IPv4 "
                                "address\n", ip);
                        goto err;
                    }
                }
                else if (strcmp(attr->key, "port") == 0) {
                    char *port_str = (char *) attr->values->data;
                    int  port      = atoi(port_str);
                    if (port == 0) {
                        fprintf(stderr, "%s is not a valid port.\n", port_str);
                        goto err;
                    }

                    /* port is valid */
                    sconf->addr.sin_port = htons(port);
                }
                else if (strcmp(attr->key, "loglevel") == 0) {
                    char *lvl = (char *) attr->values->data;
                    sconf->loglevel = lstrtoi(lvl);
                }
                else if (strcmp(attr->key, "secret") == 0) {
                    sconf->secret = malloc(strlen((char *) attr->values->data) +
                                          1);
                    if (sconf->secret == NULL) {
                        fprintf(stderr, "Mem. allocation for secret failed.\n");
                        goto err;
                    }

                    memcpy(sconf->secret, attr->values->data, 
                           strlen((char *) attr->values->data) + 1);
                }
                else if (strcmp(attr->key, "devices") == 0) {
                    /* read a list of strings representing block device files */
                    struct slist *dev_list = attr->values;
                    if (slist_empty(dev_list)) {
                        fprintf(stderr, "Specify at least one block device for "
                                "attaching to crdss-srv!\n");
                        goto err;
                    }

                    while (dev_list != NULL) {
                        char *devname     = calloc(strlen(dev_list->data) + 1,
                                                   sizeof(char));

                        if (devname == NULL) {
                            fprintf(stderr, "Failed to allocate memory for "
                                    "serverconf structure.\n");
                            goto err;
                        }

                        memcpy(devname, dev_list->data, strlen(dev_list->data));
                        if (slist_insert(&sconf->devs, devname) != 0) {
                            fprintf(stderr, "Failed to allocate memory for "
                                    "serverconf structure.\n");
                            goto err;
                        }

                        dev_list = dev_list->next;
                    }
                }
                else if (strcmp(attr->key, "guid") == 0) {
                    char *guid_str = (char *) attr->values->data;

                    sconf->guid = (uint64_t) strtoull(guid_str, NULL, 0);
                }
                else {
                    fprintf(stderr, "Ignoring unknown attribute \"%s\" in " 
                            "config element SERVER\n", attr->key);
                }

                attr_list = attr_list->next;
            }

            /* each server section must contain a valid IP address and a     *
             * valid port as well as at least one block device to manage.    */
            if (slist_length(sconf->devs) == 0) {
                fprintf(stderr, "No block devices given for server!\n");
                goto err;
            }
            if (sconf->addr.sin_addr.s_addr == 0 || sconf->addr.sin_port == 0 ||
                sconf->secret == NULL) {
                fprintf(stderr, "Missing either IP address, port number or "
                        "secret for configuration element SERVER\n");
                goto err;
            }

            if (sconf->guid == 0) {
                fprintf(stderr, "Missing server GUID for InfiniBand comm.\n");
                goto err;
            }

            /* do not forget to set the proper address family! */
            sconf->addr.sin_family = AF_INET;
            srv_flag = 1;
        }
        else if (strcmp(elm->elem_name, "SNIC") == 0) {
            /* A SNIC configuration element must have attributes "addr" (IP) *
             * and "port" (TCP port)                                         */
            struct slist *attr_list = elm->attributes;
            struct clt_capmgr *snic = NULL;

            if ((snic = malloc(sizeof(struct clt_capmgr))) == NULL) {
                fprintf(stderr, "Failed to allocate memory for server config "
                        "structure.\n");
                goto err;
            }

            snic->addr.sin_family = AF_INET;
            while (attr_list != NULL) {
                struct config_attr *attr = 
                        (struct config_attr *) attr_list->data;
                
                /* switch between different attribute names                 */
                if (strcmp(attr->key, "addr") == 0) {
                    char *ip = (char *) attr->values->data;
                    if (inet_pton(AF_INET, ip, &snic->addr.sin_addr) != 1) {
                        fprintf(stderr, "String %s is not a valid IPv4 "
                                "address\n", ip);
                        goto err;
                    }
                }
                else if (strcmp(attr->key, "port") == 0) {
                    char *port_str = (char *) attr->values->data;
                    int  port      = atoi(port_str);
                    if (port == 0) {
                        fprintf(stderr, "%s is not a valid port.\n", port_str);
                        goto err;
                    }

                    /* port is valid */
                    snic->addr.sin_port = htons(port);
                }
                else if (strcmp(attr->key, "secret") == 0) {
                    snic->secret = malloc(strlen((char *) attr->values->data) +
                                          1);
                    if (snic->secret == NULL) {
                        fprintf(stderr, "Mem. allocation for secret failed.\n");
                        goto err;
                    }

                    memcpy(snic->secret, attr->values->data, 
                           strlen((char *) attr->values->data) + 1);
                }
                else {
                    fprintf(stderr, "Ignoring unknown attribute %s in config "
                            "element SNIC\n", attr->key);
                }

                attr_list = attr_list->next;
            }

            /* check if the SNIC conf element contains mandatory attributes */
            if (snic->addr.sin_addr.s_addr == 0 || snic->addr.sin_port == 0 ||
                snic->secret == NULL) {
                fprintf(stderr, "Missing either IP address, port number or "
                        "secret for configuration element SNIC\n");
                goto err;
            }
            else if (slist_insert(&sconf->snics, snic) != 0) {
                fprintf(stderr, "Failed to allocate memory for server "
                        "config structure.\n");
                goto err;
            }

            snc_flag = 1;
        }
        else {
            fprintf(stderr, "Ignoring unknown configuration element of type "
                    "\"%s\"\n", elm->elem_name);
        }

        ptr = ptr->next;
    }

    /* check for global consistency: every server config file must have      *
     * exactly one SERVER section and at least one SNIC section.             */
    if (srv_flag == 0) {
        fprintf(stderr, "Missing server configuration element.\n");
        goto err;
    }
    if (snc_flag == 0) {
        fprintf(stderr, "No SmartNIC client specified!\n");
        goto err;
    }

    /* free raw parsing structures */
    free_raw(conf_elems);
    return(0);
err:
    /* actually, we should call a function here, that discards the newly     *
     * allocated members of sconf. However, with a bad config file, the      *
     * server will terminate anyway, so this minor memory leak will be fixed */
    free_raw(conf_elems);
    return(1);
}

/* Parses the snic configuration file located at path confpath              */
int parse_snic_config(char *confpath, struct snic_config *sconf) {
    struct slist *conf_elems;
    struct slist *ptr;
    
    int srv_flag = 0;           /* 1 if server section was defined          */
    int glb_flag = 0;           /* 1 if global SNIC attrs were defined      */
    int clt_flag = 0;           /* 1 if udp is used, 2 for domain sockets   */

    /* check if config file exists and is readable                          */
    if (access(confpath, R_OK)) {
        fprintf(stderr, "Failed to read config file %s.\n", confpath);
        return(1);
    }

    /* firstly, do raw parsing of config file                               */
    if (parse_raw(confpath, &conf_elems) != 0) {
        fprintf(stderr, "Syntax error while parsing config file %s\n", 
                confpath);
        return(2);
    }

    /* syntax in config file was ok, now check for completeness             */
    ptr = conf_elems;
    while (ptr != NULL) {
        struct config_elem *elm = (struct config_elem *) ptr->data;
        fprintf(stderr, "Elem name: %s\n", elm->elem_name);
        fprintf(stderr, "No. of attributes: %d\n", 
                slist_length(elm->attributes));

        /* check for possible configuration elements */
        if (strcmp(elm->elem_name, "GLOBAL") == 0) {
            /* SNIC global section must provide attributes "addr" and "port"*
             * for an address to bind to, may set loglevel                  */
            struct slist *attr_list = elm->attributes;

            if (glb_flag == 1) {
                fprintf(stderr, "Duplicate declaration of GLOBAL config "
                        "element\n");
                goto err;
            }

            while (attr_list != NULL) {
                struct config_attr *attr = 
                        (struct config_attr *) attr_list->data;
                
                /* switch between different attribute names                 */
                if (strcmp(attr->key, "addr") == 0) {
                    char *ip = (char *) attr->values->data;
                    if (inet_pton(AF_INET, ip, &sconf->addr.sin_addr) != 1) {
                        fprintf(stderr, "String %s is not a valid IPv4 "
                                "address\n", ip);
                        goto err;
                    }
                }
                else if (strcmp(attr->key, "loglevel") == 0) {
                    char *lvl = (char *) attr->values->data;
                    sconf->loglevel = lstrtoi(lvl);
                }
                else if (strcmp(attr->key, "secret") == 0) {
                    /* only one key string is expected */
                    char *value = (char *) attr->values->data;
                    sconf->secret = malloc(strlen(value) + 1);

                    if (sconf->secret == NULL) {
                        fprintf(stderr, "Mem. allocation for secret failed.\n");
                        goto err;
                    }

                    memcpy(sconf->secret, value, strlen(value) + 1);
                }
                /* domain socket for clients */
                else if (strcmp(attr->key, "domsock") == 0) {
                    /* path name of domain socket for clients is expected */
                    char *value = (char *) attr->values->data;
                    
                    if (clt_flag == 1) {
                        /* already configured UDP socket... */
                        fprintf(stderr, "Must either specify domain sockets OR "
                                "a UDP socket for communcation with client!\n");
                        goto err;
                    }
                    clt_flag = 2;

                    strcpy(sconf->clt_sock.dom.sun_path, value);
                }
                /* ip socket for clients */
                else if (strcmp(attr->key, "cltip") == 0) {
                    char *ip = (char *) attr->values->data;

                    if (clt_flag == 2) {
                        /* already configured domain socket... */
                        fprintf(stderr, "Must either specify domain sockets OR "
                                "a UDP socket for communcation with client!\n");
                        goto err;
                    }
                    clt_flag = 1;

                    if (inet_pton(AF_INET, ip, 
                        &sconf->clt_sock.udp.sin_addr) != 1) {
                        fprintf(stderr, "String %s is not a valid IPv4 "
                                "address\n", ip);
                        goto err;
                    }
                }
                else if (strcmp(attr->key, "cltport") == 0) {
                    char *port_str = (char *) attr->values->data;
                    int  port      = atoi(port_str);
                    
                    if (clt_flag == 2) {
                        /* already configured domain socket... */
                        fprintf(stderr, "Must either specify domain sockets OR "
                                "a UDP socket for communcation with client!\n");
                        goto err;
                    }
                    clt_flag = 1;

                    if (port == 0) {
                        fprintf(stderr, "%s is not a valid port.\n", port_str);
                        goto err;
                    }

                    /* port is valid */
                    sconf->clt_sock.udp.sin_port = htons(port);
                }
                else if (strcmp(attr->key, "guid") == 0) {
                    char *guid_str = (char *) attr->values->data;

                    sconf->guid = (uint64_t) strtoull(guid_str, NULL, 0);
                }
                else {
                    fprintf(stderr, "Ignoring unknown attribute \"%s\" in "
                            "config element GLOBAL\n", attr->key);
                }

                attr_list = attr_list->next;
            }

            /* check if the GLOBAL conf element contains mandatory attributes */
            if (sconf->addr.sin_addr.s_addr == 0 || sconf->secret == NULL) {
                fprintf(stderr, "Missing either IP address, port number or "
                        "secret for configuration element GLOBAL\n");
                goto err;
            }

            /* check if the socket information for connection to clients is  *
             * complete...                                                   */
            if (clt_flag == 1) {
                if (sconf->clt_sock.udp.sin_addr.s_addr == 0 ||
                    sconf->clt_sock.udp.sin_port == 0) {
                    fprintf(stderr, "Missing either IP address or port no. "
                            "for UDP socket to clients!\n");
                    goto err;
                }

                sconf->clt_sock.udp.sin_family = AF_INET;
            }
            else if (clt_flag == 2) {
                if (strlen(sconf->clt_sock.dom.sun_path) == 0) {
                    fprintf(stderr, "Specified invalid path for domain socket "
                            "for client connections!\n");
                    goto err;
                }

                sconf->clt_sock.dom.sun_family = AF_UNIX;
            }
            else {
                fprintf(stderr, "Specify either a UDP or a domain socket for "
                        "communication with clients.\n");
                goto err;
            }

            /* if everythinig is ok, do not forget to set the address family */
            sconf->addr.sin_family     = AF_INET;
            glb_flag = 1;
        }
        else if (strcmp(elm->elem_name, "SERVER") == 0) {
            /* A SERVER configuration element must have attributes "addr"   *
             * (IP) and "port" (TCP port)                                   */
            struct slist *attr_list = elm->attributes;
            struct srv_conn *srv = NULL;

            if ((srv = malloc(sizeof(struct srv_conn))) == NULL) {
                fprintf(stderr, "Failed to allocate memory for server config "
                        "structure.\n");
                goto err;
            }

            srv->addr.sin_family = AF_INET;
            while (attr_list != NULL) {
                struct config_attr *attr = 
                        (struct config_attr *) attr_list->data;
                
                /* switch between different attribute names                 */
                if (strcmp(attr->key, "addr") == 0) {
                    char *ip = (char *) attr->values->data;
                    if (inet_pton(AF_INET, ip, &srv->addr.sin_addr) != 1) {
                        fprintf(stderr, "String %s is not a valid IPv4 "
                                "address\n", ip);
                        goto err;
                    }
                }
                else if (strcmp(attr->key, "port") == 0) {
                    char *port_str = (char *) attr->values->data;
                    int  port      = atoi(port_str);
                    if (port == 0) {
                        fprintf(stderr, "%s is not a valid port.\n", port_str);
                        goto err;
                    }

                    /* port is valid */
                    srv->addr.sin_port = htons(port);
                }
                else if (strcmp(attr->key, "lport") == 0) {
                    /* local port that shall be used for comm. with server  */
                    char *port_str = (char *) attr->values->data;
                    int  port      = atoi(port_str);
                    if (port == 0) {
                        fprintf(stderr, "%s is not a valid port.\n", port_str);
                        goto err;
                    }

                    /* port is valid */
                    srv->lport = htons(port);
                }
                else if (strcmp(attr->key, "secret") == 0) {
                    /* identification key sent by server */
                    srv->secret = malloc(strlen((char *) attr->values->data) +
                                         1);
                    if (srv->secret == NULL) {
                        fprintf(stderr, "Mem. allocation for secret failed.\n");
                        goto err;
                    }

                    memcpy(srv->secret, attr->values->data,
                           strlen((char *) attr->values->data) + 1);
                }
                else {
                    fprintf(stderr, "Ignoring unknown attribute %s in config "
                            "element SERVER\n", attr->key);
                }

                attr_list = attr_list->next;
            }

            /* check if the SNIC conf element contains mandatory attributes */
            if (srv->addr.sin_addr.s_addr == 0 || srv->addr.sin_port == 0 ||
                srv->lport == 0 || srv->secret == 0) {
                fprintf(stderr, "Missing either IP address, port number, "
                        "local port number or secret for configuration element "
                        "SERVER\n");
                goto err;
            }
            else if (slist_insert(&sconf->srvs, srv) != 0) {
                fprintf(stderr, "Failed to allocate memory for server "
                        "config structure.\n");
                goto err;
            }

            srv->addr.sin_family = AF_INET;
            srv_flag = 1;
        }
        else if (strcmp(elm->elem_name, "CAP") == 0) {
            /* read client capabilities from config file                    */
            struct slist *attr_list   = elm->attributes;
            struct crdss_clt_cap *cap = NULL;

            if ((cap = malloc(sizeof(struct crdss_clt_cap))) == NULL) {
                fprintf(stderr, "Failed to allocate memory for capmgr config "
                        "structure.\n");
                goto err;
            }

            while (attr_list != NULL) {
                struct config_attr *attr =
                            (struct config_attr *) attr_list->data;
                attr_list = attr_list->next;

                /* switch between attribute names */
                if (strcmp(attr->key, "server") == 0) {
                    char *ip = (char *) attr->values->data;
                    if (inet_pton(AF_INET, ip, &cap->srv.sin_addr) != 1) {
                        fprintf(stderr, "String %s is not a valid IPv4 "
                                "address\n", ip);
                        goto err;
                    }
                }
                else if (strcmp(attr->key, "dev_idx") == 0) {
                    char *idx_str = (char *) attr->values->data;
                    cap->dev_idx  = (uint16_t) atoi(idx_str);
                }
                else if (strcmp(attr->key, "vslc_idx") == 0) {
                    char *idx_str = (char *) attr->values->data;
                    cap->vslc_idx = (uint32_t) atoi(idx_str);
                }
                else if (strcmp(attr->key, "start_addr") == 0) {
                    char *addr_str  = (char *) attr->values->data;
                    cap->start_addr = (uint64_t) atol(addr_str);
                }
                else if (strcmp(attr->key, "end_addr") == 0) {
                    char *addr_str = (char *) attr->values->data;
                    cap->end_addr  = (uint64_t) atoi(addr_str);
                }
                else if (strcmp(attr->key, "rights") == 0) {
                    cap->rights = permstrtoi(attr->values);
                }
                else if (strcmp(attr->key, "uid") == 0) {
                    char *uid_str = (char *) attr->values->data;
                    cap->uid      = (uid_t) atoi(uid_str);
                }
                else if (strcmp(attr->key, "key") == 0) {
                    /* identification key sent by server */
                    cap->key = malloc(strlen((char *) attr->values->data) + 1);
                    if (cap->key == NULL) {
                        fprintf(stderr, "Mem. allocation for key failed.\n");
                        goto err;
                    }

                    memcpy(cap->key, attr->values->data,
                           strlen((char *) attr->values->data) + 1);
                }
                else {
                    fprintf(stderr, "Ignoring unknown attribute \"%s\" in "
                            "config element CAP.\n", attr->key);
                }
            }

            /* check for completeness of cap config. however, values may be *
             * arbitrary, so just a valid server IP is required             */
            if (cap->srv.sin_addr.s_addr == 0) {
                fprintf(stderr, "No valid server IP address found for cap.");
                goto err;
            }
            if (slist_insert(&sconf->caps, cap)) {
                fprintf(stderr, "Failed to allocate mem. for list insertion.");
                goto err;
            }
        }
        else {
            fprintf(stderr, "Ignoring unknown configuration element of type "
                    "%s\n", elm->elem_name);
        }

        ptr = ptr->next;
    }

    /* check for global consistency: every snic config file must have        *
     * exactly one GLOBAL section and at least one SERVER section.           */
    if (srv_flag == 0) {
        fprintf(stderr, "Specify at least one crdss server to connect to.\n");
        goto err;
    }
    if (glb_flag == 0) {
        fprintf(stderr, "Missing GLOBAL configuration element.\n");
        goto err;
    }

    /* free raw parsing structures */
    free_raw(conf_elems);
    return(0);
err:
    /* actually, we should call a function here, that discards the newly     *
     * allocated members of sconf. However, with a bad config file, the      *
     * server will terminate anyway, so this minor memory leak will be fixed */
    free_raw(conf_elems);
    return(1);
}

/* Parses a configuration file for the client library.                      */
int parse_lib_config(char *confpath, struct clt_lib_cfg *cconf) {
    struct slist *conf_elems;
    struct slist *ptr;
    
    int lib_flag = 0;           /* 1 if library config was already defined  */
    
    /* check if config file exists and is readable                          */
    if (access(confpath, R_OK)) {
        fprintf(stderr, "Failed to read config file %s.\n", confpath);
        return(1);
    }

    /* firstly, do raw parsing of config file                               */
    if (parse_raw(confpath, &conf_elems) != 0) {
        fprintf(stderr, "Syntax error while parsing config file %s\n", 
                confpath);
        return(2);
    }

    /* syntax in config file was ok, now check for completeness             */
    ptr = conf_elems;
    while (ptr != NULL) {
        struct config_elem *elm = (struct config_elem *) ptr->data;
        
        /*
        fprintf(stderr, "Elem name: \"%s\"\n", elm->elem_name);
        fprintf(stderr, "No. of attributes: %u\n", 
                slist_length(elm->attributes));
        */
        
        /* check for possible configuration elements */
        if (strcmp(elm->elem_name, "LIB") == 0) {
            /* a SERVER config element must have attributes "addr" (IP),    *
             * port and devices. It may have a setting for the log level    */
            /* fprintf(stderr, "Starting processing of SERVER element.\n"); */

            if (lib_flag == 1) {
                fprintf(stderr, "Duplicate declaration of LIB config "
                        "element\n");
                goto err;
            }

            /* mind that buffers sizes in config file are given in KiB!     */

            struct slist *attr_list = elm->attributes;    /* attribute list */
            while (attr_list != NULL) {
                struct config_attr *attr = 
                    (struct config_attr *) attr_list->data;
                
                /* fprintf(stderr, "Processing attr %s\n", attr->key); */
                /* switch between different attribute names                 */
                if (strcmp(attr->key, "no_workers") == 0) {
                    char *cnt = (char *) attr->values->data;
                    cconf->no_workers = strtoul(cnt, NULL, 0);
                }
                else if (strcmp(attr->key, "sbuf_size") == 0) {
                    char *sz = (char *) attr->values->data;
                    cconf->sbuf_size = strtoul(sz, NULL, 0) * 1024;
                }
                else if (strcmp(attr->key, "lbuf_size") == 0) {
                    char *sz = (char *) attr->values->data;
                    cconf->lbuf_size = strtoul(sz, NULL, 0) * 1024;
                }
                else if (strcmp(attr->key, "lbuf_cnt") == 0) {
                    char *cnt = (char *) attr->values->data;
                    cconf->lbuf_cnt = strtoul(cnt, NULL, 0);
                }
                else {
                    fprintf(stderr, "Ignoring unknown attribute \"%s\" in " 
                            "config element LIB\n", attr->key);
                }

                attr_list = attr_list->next;
            }

            /* do sanity check for LIB config element */
            if (check_libcfg(cconf) != 0) {
                fprintf(stderr, "Libary configuration is incomplete.\n");
                goto err;
            }

            /* library config has been set */
            lib_flag = 1;
        }
        else {
            fprintf(stderr, "Ignoring unknown configuration element of type "
                    "\"%s\"\n", elm->elem_name);
        }

        ptr = ptr->next;
    }

    /* free raw parsing structures */
    free_raw(conf_elems);
    return(0);
err:
    /* since the library config does not contain deeply nested types, no    *
     * special destructor needs to be executed for it.                      */
    free_raw(conf_elems);
    return(3);
}

/* Checks the sanity of a configuration object for libcrdss.                */
int check_libcfg(struct clt_lib_cfg *cfg) {
    if (cfg->no_workers == 0) {
        fprintf(stderr, "Invalid value for worker count.\n");
        return(1);
    }

    if (cfg->sbuf_size == 0) {
        fprintf(stderr, "Invalid value for sbuf_size parameter.\n");
        return(2);
    }

    if (cfg->lbuf_size == 0) {
        fprintf(stderr, "Invalid value for lbuf_size parameter.\n");
        return(3);
    }

    if (cfg->lbuf_cnt == 0) {
        fprintf(stderr, "Found invalid value for lbuf_cnt.\n");
        return(4);
    }

    return(0);
}
