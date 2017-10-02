/*
 * sysXtract
 *
 * Copyright 2017 nkk71 <nkk71x@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 */

/* $Header: /home/ksheff/src/e2tools/RCS/ls.c,v 0.8 2004/04/07 03:30:49 ksheff Exp $ */
/*
 * ls.c --- list directories
 *
 * Copyright (C) 1997 Theodore Ts'o.  This file may be redistributed
 * under the terms of the GNU Public License.
 *
 * Modified by Keith W. Sheffield <shefff@pobox.com> for inclusion with e2tools
 */
/*
 * $Log: ls.c,v $
 * Revision 0.8  2004/04/07 03:30:49  ksheff
 * Updated usage string.
 *
 * Revision 0.7  2004/04/07 02:41:50  ksheff
 * Modified to bracket files with an inode number of 0 with >< characters.
 *
 * Revision 0.6  2004/04/06 20:27:26  ksheff
 * Modified to print "No files found!" for empty directories, corrected the
 * directory name display, and fixed REGEX_OPT masking.
 *
 * Revision 0.5  2002/06/05 23:14:11  ksheff
 * Fixed short display with respect to displaying the contents of multiple
 * directories.
 *
 * Revision 0.4  2002/06/05 23:07:34  ksheff
 * Allowed for multiple directory and file specifications.  Added the -f
 * option for no sorting.
 *
 * Revision 0.3  2002/06/03 23:00:51  ksheff
 * Removed display code from directory iterator.  A list of displayable files
 * is now generated.  This list can be sorted and displayed in a variety of
 * ways.  The -a, -c, -i, -r, and -t options are now accepted.
 *
 * Revision 0.2  2002/03/05 12:12:52  ksheff
 * Removed setting optind for SCO.
 *
 * Revision 0.1  2002/02/27 04:46:21  ksheff
 * initial revision
 *
 */


#include "e2tools.h"
#include "elist.h"
#include <regex.h>
#include <stdint.h>
#include <inttypes.h>
#include <pwd.h>
#include <grp.h>

#define VERSION_STR "0.8.1"

/*
 * list directory
 */

#define LONG_OPT    0x0001
#define DELETED_OPT 0x0002
#define REGEX_OPT   0x0004
#define REVERSE_OPT 0x0008
#define HIDDEN_OPT  0x0010
#define CREATE_OPT  0x0020
#define INODE_OPT   0x0040
#define NUMERIC_OPT 0x0080
#define SHORT_OPT   0x0100
#define FS_CONFIG_OPT 0x0200
#define RECURSIVE_OPT 0x0400
#define EXCL_LNK_OPT  0x0800
#define EXCL_DIR_OPT  0x1000
#define EXCL_REG_OPT  0x2000
#define EXCL_NONCAPS_OPT 0x4000

#define DIRECTORY_TYPE -1
#define NORMAL_TYPE 0

struct list_dir_struct {
	int options;
	regex_t *reg;
	elist_t *files;
};

typedef struct list_file_struct {
	char *name;
	char *full_name;
	struct ext2_inode inode;
	ext2_ino_t dir;
	ext2_ino_t inode_num;
	int entry;
	long type;
} ls_file_t;

static const char *monstr[] = {
	"Jan", "Feb", "Mar", "Apr", "May", "Jun",
	"Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
};


/* Things we need for selinux and capabilities */
#define XATTR_SELINUX_SUFFIX "selinux"
#define XATTR_CAPS_SUFFIX "capability"
#define VFS_CAP_U32 2

struct vfs_cap_data {
 __le32 magic_etc;
 struct {
 __le32 permitted;
 __le32 inheritable;
 } data[VFS_CAP_U32];
};


/* global variables */
static ext2_filsys fs;
static int max_name_len = 0;

// for recursion and multiple dir specs
static elist_t *Dirs_To_List = NULL;
static char *Current_Path = NULL;

// path prefix for fs_config format
static char *fs_config_Path_Prefix = NULL;

// output files
static char *extract_path = NULL;
static FILE *fp_file_contexts = NULL;
static FILE *fp_C_fs_config = NULL;
static FILE *fp_X_fs_config = NULL;
static FILE *fp_D_listing = NULL;
static FILE *fp_symlinks = NULL;

static int g_count_dir = 0;
static int g_count_reg = 0;
static int g_count_lnk = 0;
static int g_count_unknown = 0;

static int g_verbose = 1;

/* forward function declarations */
static int list_dir_proc(ext2_ino_t dir, int entry, struct ext2_dir_entry *dirent, int offset, int blocksize, char *buf, void *private);
void free_ls_file_t(void *f);
void fprintf_long_disp(FILE *fp, ls_file_t *info, const char *selinux_context, struct vfs_cap_data *capabilities, char *symlink_dest, int options);
int full_name_sort(const void *n1, const void *n2);
long add_ls_file(char *name, int namelen, ext2_ino_t dir, ext2_ino_t ino, int entry, int type, struct list_dir_struct *ls);
elist_t *remove_ls_dups(elist_t *list);
void extract_file(ls_file_t *info, int options);


char *strdupcat_sanitized(const char *path, const char *file)
{
	int path_len;
	int file_len;
	char *full_name;
	char *p = path;
	int needs_slash = 0;

	if (!path && !file)
		return NULL;
	else if (!path)
		return strdup(file);

	// remove leading / and .
	/*
	 * do not remove leading . that will just break hidden
	 * dirs in the base folder, instead fix the command
	 * line parsing when given paths
	while (p[0] == '/' || p[0] == '.')
		p++;
	*/

	path_len = strlen(p);
	file_len = strlen(file);

	if (path_len > 0 && p[path_len-1] != '/' && file[0] != '/')
		needs_slash = 1;

	full_name = malloc(path_len + needs_slash + file_len + 1);

	if (!full_name) {
		perror("malloc");
		return NULL;
	}

	memcpy(full_name, p, path_len);
	full_name[path_len] = '/'; // don't really need to if() it
	memcpy(full_name + path_len + needs_slash, file, file_len + 1);

	return full_name;
}


#if 1
/* ********************************************************************************** */
/* my_strcmp() from copy.c */
int my_strcmp(const void *n1, const void *n2)
{
	char *s1 = *((char **)n1);
	char *s2 = *((char **)n2);

	return(strcmp(s1, s2));
}

/* change_cwd() from mkdir.c */
/* Name:    change_cwd()
 *
 * Description:
 *
 * This function changes the current working directory
 *
 * Algorithm:
 *
 * Look up the inode number for the input string
 * check to see if it's a directory
 * Assign it as the current working directory if it is.
 *
 * Global Variables:
 *
 * None
 *
 * Arguments:
 *
 * ext2_filsys fs;         The current filesystem
 * ext_ino_t root;         The root directory
 * ext_ino_t *cwd;         The current working directory
 * char *dirname;          The name of the directory we want to change to
 *
 * Return Values:
 *
 * 0 - changed to the directory successfully
 * the error code of what went wrong
 *
 * Author: Keith W Sheffield
 * Date:   02/21/2002
 *
 * Modification History:
 *
 * MM/DD/YY      Name               Description
 *
 */
long
change_cwd(ext2_filsys fs, ext2_ino_t root, ext2_ino_t *cwd, char *dirname)
{
  ext2_ino_t inode;
  long retval;

  if ((retval = ext2fs_namei(fs, root, *cwd, dirname, &inode)))
    {
      fprintf(stderr, "%s\n", error_message(retval));
      return retval;
    }
  else if ((retval = ext2fs_check_directory(fs, inode)))
    {
      fprintf(stderr, "%s\n", error_message(retval));
      return retval;
    }
  *cwd = inode;
  return(0);
} /* end of change_cwd */

/* get_file_parts() from mv.c */
/* Name:    get_file_parts()
 *
 * Description:
 *
 * This function returns each of the following file 'parts': directory name,
 * base name, inode number of the directory
 *
 * Algorithm:
 *
 * Use the root directory as the current working directory
 * Find the last / in the full pathname
 *     If none are found, set the basename to the full pathname,
 *     and the directory to NULL
 * Otherwise,
 *     Separate the basename from the directory
 *     Change the working directory
 * Set the return pointers.
 *
 * Global Variables:
 *
 * None.
 *
 * Arguments:
 *
 * ext2_filsys fs;            the filesystem being used
 * ext2_ino_t root;           the root directory of the filesystem
 * char *pathname;            the full pathname of the file
 * ext2_ino_t *dir_ino;       The inode number of the directory
 * char **dir_name;           the directory the file is in
 * char **base_name;          The basename of the file
 *
 * Return Values:
 *
 * 0 - retrieved the information ok
 * otherwise the error code of what went wrong
 *
 * Author: Keith W. Sheffield
 * Date:   03/21/2002
 *
 * Modification History:
 *
 * MM/DD/YY      Name               Description
 *
 */
long
get_file_parts(ext2_filsys fs, ext2_ino_t root, char *pathname,
               ext2_ino_t *dir_ino, char **dir_name, char **base_name)
{
  char *fname;
  long retval;

  /* move to the source directory */
  *dir_name = pathname;
  *dir_ino = root;
  if (NULL == (fname = strrchr(pathname, '/')))
    {
      fname = pathname;
      *dir_name = NULL;
    }
  else
    {
      *fname++ = '\0';
      if ((*pathname != '\0' && strcmp(pathname, ".") != 0) &&
          (retval = change_cwd(fs, root, dir_ino, pathname)))
        {
          fprintf(stderr, "Error changing to directory %s\n",
                  pathname);
          return(retval);
        }
    }

    *base_name = fname;
    return(0);
} /* end of get_file_parts */
/* ********************************************************************************** */
#endif


/* Name:    list_dir_proc()
 *
 * Description:
 *
 *
 * Algorithm:
 *
 *
 * Global Variables:
 *
 * None
 *
 * Arguments:
 *
 *
 * Return Values:
 *
 *
 * Author: Theodore Ts'o
 * Date:   1997
 *
 * Modification History:
 *
 * MM/DD/YY      Name               Description
 * 02/27/02      K.Sheffield        Modified for use with e2tools
 */
static int list_dir_proc(ext2_ino_t dir, int entry, struct ext2_dir_entry *dirent,
                         int UNUSED_PARM(offset), int UNUSED_PARM(blocksize),
                         char UNUSED_PARM(*buf), void *private)
{
	char name[EXT2_NAME_LEN];
	struct list_dir_struct *ls = (struct list_dir_struct *) private;
	int thislen;

	thislen = ((dirent->name_len & 0xFF) < EXT2_NAME_LEN) ? (dirent->name_len & 0xFF) : EXT2_NAME_LEN;
	strncpy(name, dirent->name, thislen);
	name[thislen] = '\0';

	/* skip hidden files unless we ask for them */
	if (0 == (ls->options & HIDDEN_OPT) && name[0] == '.')
		return(0);

	// always skip . and ..
	if (name[0] == '.' && (name[1] == 0 || (name[1] == '.' && name[2] == 0)))
		return(0);

	if ((ls->options & REGEX_OPT) && regexec(ls->reg, name, 0, NULL, 0))
		return(0);

	return(add_ls_file(name, thislen, dir, dirent->inode, entry, NORMAL_TYPE, ls));
}

/* Name:    add_ls_file()
 *
 * Description:
 *
 *
 * Algorithm:
 *
 *
 * Global Variables:
 *
 * None
 *
 * Arguments:
 *
 *
 * Return Values:
 *
 *
 * Author: K.Sheffield
 * Date:   02/27/2002
 *
 * Modification History:
 *
 * MM/DD/YY      Name               Description
 */
long add_ls_file(char *name, int namelen, ext2_ino_t dir, ext2_ino_t ino,
                 int entry, int type, struct list_dir_struct *ls)
{
	ls_file_t *file_info;
	elist_t *flist;

	if (NULL == (file_info = calloc(sizeof(ls_file_t),1))) {
		perror("list_dir");
		return(0);
	}

	file_info->dir = dir;

	if (entry == DIRENT_DELETED_FILE)
		file_info->inode_num = 0;
	else
		file_info->inode_num = ino;

	file_info->entry = entry;
	file_info->type = type;

	if (file_info->inode_num) {
		if (read_inode(fs, file_info->inode_num, &file_info->inode)) {
			free(file_info);
			return 0;
		}
	}

	if (file_info->inode_num) {
		if (LINUX_S_ISDIR(file_info->inode.i_mode))
			g_count_dir++;
		else if (LINUX_S_ISREG(file_info->inode.i_mode))
			g_count_reg++;
		else if  (LINUX_S_ISLNK(file_info->inode.i_mode))
			g_count_lnk++;
		else
			g_count_unknown++;
	}

	if (name) {
		file_info->name = strdup(name);
		if (type == DIRECTORY_TYPE)
			file_info->full_name = strdupcat_sanitized("", name);
		else
			file_info->full_name = strdupcat_sanitized(Current_Path, name);
	}

	if (NULL == (flist = elist_insert(ls->files, file_info))) {
		perror("list_dir");
		free_ls_file_t(file_info);
		return 0;
	}
	ls->files = flist;

	if (max_name_len < namelen)
		max_name_len = namelen;

	if ((ls->options & RECURSIVE_OPT) && type == NORMAL_TYPE && LINUX_S_ISDIR(file_info->inode.i_mode) && !LINUX_S_ISLNK(file_info->inode.i_mode)) {
		// if we're recursing append this dir to the list
		Dirs_To_List = elist_append(Dirs_To_List, strdup(file_info->full_name));
	}

	return 0;
}

/* Name:    free_ls_file_t()
 *
 * Description:
 *
 * This function is used to free an ls_file_t structure.
 *
 * Algorithm:
 *
 * Free the file's name if it is not NULL
 * Free the ls_file_t structure
 * Check to make sure the ls_file_t structure is not NULL
 *
 * Global Variables:
 *
 * None.
 *
 * Arguments:
 *
 * void *f;                The structure to free
 *
 * Return Values:
 *
 * none
 *
 * Author: Keith W. Sheffield
 * Date:   06/03/2002
 *
 * Modification History:
 *
 * MM/DD/YY      Name               Description
 *
 */
void free_ls_file_t(void *f)
{
	ls_file_t *n = (ls_file_t *) f;

	if (n != NULL) {
		if (n->name != NULL)
			free(n->name);
		if (n->full_name != NULL)
			free(n->full_name);
		free(n);
	}
} /* end of free_ls_file_t */


int main(int argc, char *argv[])
{
	ext2_ino_t root;
	ext2_ino_t cwd;
	ext2_ino_t inode=0;
	int retval;
	int c;
	int flags;
	struct list_dir_struct ls;
	char *fs_name;
	char *last_fs_name;
	char *path = NULL;
	char *dup_path = NULL;
	char *dir_name;
	char *base_name;
	elist_t *files=NULL;
	ls_file_t *cur_file;

	memset(&ls, 0, sizeof(ls));

	last_fs_name = NULL;
#ifdef HAVE_OPTRESET
	optreset = 1;     /* Makes BSD getopt happy */
#endif

	// default for make_fs_config
	ls.options |= FS_CONFIG_OPT;

	while ((c = getopt (argc, argv, "C:D:d:F:L:p:qRS:X:x:")) != EOF) {
		switch (c) {
			case 'd':
				fs_name = optarg;
				if (NULL != (path = strchr(fs_name, ':')))
					*path++ = '\0';
				if ((retval = open_filesystem(fs_name, &fs, &root, 0))) {
					return(1);
				}
				last_fs_name = fs_name;
				break;
			case 'R':
				ls.options |= RECURSIVE_OPT;
				break;
			case 'p':
				fs_config_Path_Prefix = optarg;
				break;
			case 'x':
				while (optarg && optarg[0]) {
					if (optarg[0] == 'L')
						ls.options |= EXCL_LNK_OPT;
					else if (optarg[0] == 'D')
						ls.options |= EXCL_DIR_OPT;
					else if (optarg[0] == 'R')
						ls.options |= EXCL_REG_OPT;
					else if (optarg[0] == 'N')
						ls.options |= EXCL_NONCAPS_OPT;
					optarg++;
				}
				break;
			case 'S':
				fp_file_contexts = fopen(optarg, "w");
				break;
			case 'C':
				fp_C_fs_config = fopen(optarg, "w");
				break;
			case 'X':
				fp_X_fs_config = fopen(optarg, "w");
				break;
			case 'L':
				fp_symlinks = fopen(optarg, "w");
				break;
			case 'F':
				extract_path = optarg;
				break;
			case 'D':
				fp_D_listing = fopen(optarg, "w");
				break;
			case 'q':
				g_verbose = 0;
				break;
		}
	}

	// show hidden files
	ls.options |= HIDDEN_OPT;

	// always use numeric format
	ls.options |= NUMERIC_OPT;

	if (argc <= optind) {
		fputs("\n"
		      "Usage: sysXtract " VERSION_STR " [-qR][-xLDRN][-F dir][-D file][-L file][-p prefix][-S file][-C file][-X file] file\n\n"
		      "       [-q]                    Quieter (don't continuously print progress while extracting files)\n"
		      "       [-R]                    List subdirectories recursively\n"
		      "       [-x LDRN]               Exclude [L]symlinks  [D]directories  [R]regular files  [N]files without capabilities\n"
		      "       [-F OutputDir]          Directory to extract regular files to\n"
		      "       [-D dir_listing]        File to output ls -lRZ style output\n"
		      "       [-L symlink_list]       File to output symlink informtion\n"
		      "       [-p prefix]             Prefix used for below file_contexts and fs_config entries\n"
		      "       [-S file_contexts]      File to output file_contexts information\n"
		      "       [-C fs_config]          File to output complete fs_config information\n"
		      "       [-X xtra_fs_config]     File to output capabilities-only fs_config\n"
		      "       file                    ext4 image file to be processed\n"
		      "\n", stderr);
		return(1);
	}

	fprintf(stderr, "\n");
	fprintf(stderr, "sysXtract " VERSION_STR "\n");

	/* sort the remaining command line arguments */
	//qsort(argv+optind, argc-optind, sizeof(char *), my_strcmp);

	for(c=optind;c<argc;c++) {
		fs_name = argv[c];

		if (NULL != (path = strchr(fs_name, ':')))
			*path++ = '\0';
		else if (last_fs_name != NULL) {
			path = fs_name;
			fs_name = last_fs_name;
		}

		if (Dirs_To_List) {
			elist_free(Dirs_To_List, free);
			Dirs_To_List = NULL;
		}

		// TODO: mkdir_recursive on base path if specified (make sure to exclude file is it's a file)
		if (path)
			Dirs_To_List = elist_append(Dirs_To_List, strdup(path));
		else
			Dirs_To_List = elist_append(Dirs_To_List, strdup(""));

		elist_t *itr = Dirs_To_List;
		while (itr && itr->data) {
			path = itr->data;

			/* keep a copy of the file path for later because get_file_parts() is
			 * destructive.
			 */

			if (dup_path) {
				free(dup_path);
				dup_path = NULL;
			}

			if (path)
				dup_path = strdup(path);

			if (last_fs_name == NULL || strcmp(last_fs_name, fs_name)) {
				if (last_fs_name != NULL)
					ext2fs_close(fs);

				if ((retval = open_filesystem(fs_name, &fs, &root, 0))) {
					return(1);
				}
				fprintf(stderr, "Reading '%s'\n", fs_name);
				last_fs_name = fs_name;
			}

			dir_name = NULL;
			cwd = root;
			ls.options &= (~REGEX_OPT);

			if (path != NULL && *path != '\0') {
				if (get_file_parts(fs, root, path, &cwd, &dir_name, &base_name)) {
					ext2fs_close(fs);
					return(-1);
				}

				if (is_file_regexp(base_name)) {
					if (NULL == (ls.reg = (regex_t *) make_regexp(base_name))) {
						fprintf(stderr, "Error creating regular expression for %s\n", base_name);
						return(1);
					}
					ls.options |= REGEX_OPT;
					inode = cwd;
				}
				/* check to see if the file name exists in the current directory
				 */
				else if ((retval = ext2fs_namei(fs, cwd, cwd, base_name, &inode))) {
					fputs(error_message(retval), stderr);
					ext2fs_close(fs);
					return(1);
				}
			}
			else
				inode = root;

			if(!dir_name)
				dir_name = ".";

			if (!inode)
				continue;

			flags = DIRENT_FLAG_INCLUDE_EMPTY;
			if (ls.options & DELETED_OPT)
				flags |= DIRENT_FLAG_INCLUDE_REMOVED;

			if ((retval = ext2fs_check_directory(fs, inode))) {
				if (retval != EXT2_ET_NO_DIRECTORY) {
					fputs(error_message(retval), stderr);
					ext2fs_close(fs);
					return(1);
				}

				if(add_ls_file(dir_name, 0, cwd, 0, 0, DIRECTORY_TYPE, &ls)) {
					fputs(error_message(retval), stderr);
					ext2fs_close(fs);
					return(1);
				}

				if(add_ls_file(base_name, strlen(base_name), cwd, inode, 0, NORMAL_TYPE, &ls)) {
					fputs(error_message(retval), stderr);
					ext2fs_close(fs);
					return(1);
				}
			}
			else {
				if (ls.options & REGEX_OPT || path == NULL || *path == '\0')
					path = dir_name;
				else if (dup_path)
					path = dup_path;

				// we need to set a global variable so it can be picked up by add_ls_file()
				Current_Path = dup_path;


				//        if(add_ls_file((ls.options & REGEX_OPT) ? dir_name : path, 0, inode, 0,
				if(add_ls_file(path, 0, inode, 0, 0, DIRECTORY_TYPE, &ls)) {
					fputs(error_message(retval), stderr);
					ext2fs_close(fs);
					return(1);
				}

				retval = ext2fs_dir_iterate2(fs, inode, flags, 0, list_dir_proc, &ls);
				if (retval) {
					fputs(error_message(retval), stderr);
					ext2fs_close(fs);
					return(1);
				}
			}
			itr = itr->next;
		}
		elist_free(Dirs_To_List, free);
		Dirs_To_List = NULL;
	}

	fprintf(stderr, "Scan complete:\n");
	fprintf(stderr, "    %6d directories\n", g_count_dir);
	fprintf(stderr, "    %6d regular files\n", g_count_reg);
	fprintf(stderr, "    %6d symlinks\n", g_count_lnk);
	if (g_count_unknown) {
		fprintf(stderr, "    %6d unknown entries! Please inform the developer!\n", g_count_unknown);
	}
	int total_count = g_count_dir + g_count_reg + g_count_lnk + g_count_unknown;

	fprintf(stderr, "Sorting and removing duplicates\n");

	elist_sort(ls.files, full_name_sort, ls.options & REVERSE_OPT);

	ls.files = files = remove_ls_dups(ls.files);

	if (files == NULL)
		fprintf(stderr, "No files found!");
	else {
		if (!g_verbose && extract_path) {
			fprintf(stderr, "Extracting %d entries please wait...", total_count);
		}

		while(files != NULL) {
			cur_file = (ls_file_t *)files->data;

#if 0
			// does not work properly (probably due to sort)
			if (fp_D_listing && cur_file->type == DIRECTORY_TYPE) {
				fprintf(fp_D_listing, "\n%s:\n", cur_file->full_name);
			}
#endif

			if (cur_file->type != DIRECTORY_TYPE) {
				extract_file(cur_file, ls.options);
				if (g_verbose && extract_path) {
					fprintf(stderr, "\rExtracting files: %d remaining    \r",--total_count);
				}
			}
			//~ else
				//~ printf("mkdir %s\n", cur_file->full_name);

			files = files->next;
		}
	}
	//fprintf(stderr, "\rExtracting files: 0 remaining    \r");

	fputc('\n', stderr);

	elist_free(ls.files, free_ls_file_t);

	if (fp_file_contexts)
		fclose(fp_file_contexts);
	if (fp_C_fs_config)
		fclose(fp_C_fs_config);
	if (fp_X_fs_config)
		fclose(fp_X_fs_config);
	if (fp_symlinks)
		fclose(fp_symlinks);

	if (fs)
		ext2fs_close(fs);

	fprintf(stderr, "Finished.\n\n");
	return(0);
}


char *read_xattr(ext2_ino_t inode_num, const char *attribute)
{
	char *ret = NULL;
	struct ext2_xattr_handle *h;
	char *buf = NULL;
	size_t buflen;
	errcode_t err;
	unsigned int handle_flags = 0;

	err = ext2fs_xattrs_open(fs, inode_num, &h);
	if (err)
		goto out2;

	err = ext2fs_xattrs_flags(h, &handle_flags, NULL);
	if (err)
		goto out;

	err = ext2fs_xattrs_read(h);
	if (err)
		goto out;

	err = ext2fs_xattr_get(h, attribute, (void **)&buf, &buflen);
	if (err)
		goto out;

	ret = malloc(buflen);
	if (ret)
		memcpy(ret, buf, buflen);

	ext2fs_free_mem(&buf);
out:
	ext2fs_xattrs_close(&h);
	// Might not be an error just no capabilities
	/* if (err)
		com_err("xattrs_get", err, "while getting extended attribute"); */
out2:
	return ret;
}

void fprintf_symlink_entry(FILE *fp, ls_file_t *info, char *symlink_dest)
{
	// edify format:
	// fprintf(fp, "symlink(\"%s\", \"/%s\");\n", symlink_dest, info->full_name);

	fprintf(fp, "%-30s   ->   %s\n", info->full_name, symlink_dest);
}

void fprintf_file_contexts_entry(FILE *fp, ls_file_t *info, const char *selinux_context)
{
	if (fs_config_Path_Prefix) {
		if (fs_config_Path_Prefix[0] == '/')
			fprintf(fp, "%s", fs_config_Path_Prefix);
		else
			fprintf(fp, "/%s", fs_config_Path_Prefix); // add leading / for file_contexts
	}
	else
		fprintf(fp,"/"); // add leading / for file_contexts

	fprintf(fp, "%-50s   %s\n", info->full_name, selinux_context);
}

void fprintf_fs_config_entry(FILE *fp, ls_file_t *info, struct vfs_cap_data *capabilities)
{
	// full_name  uid  gid  mode [capabilities=caps]

	if (fs_config_Path_Prefix) {
		if (fs_config_Path_Prefix[0] == '/')
			fprintf(fp, "%s", fs_config_Path_Prefix + 1); // strip leading / for fs_config
		else
			fprintf(fp, "%s", fs_config_Path_Prefix);
	}

	fprintf(fp, "%-50s   ", info->full_name);
	fprintf(fp, "%05d  %05d  ", info->inode.i_uid, info->inode.i_gid);
	fprintf(fp, "%05o", info->inode.i_mode & 07777);

	/* Capabilities (struct vfs_cap_data) are stored as follows:
	 *    cap_data.magic_etc = VFS_CAP_REVISION | VFS_CAP_FLAGS_EFFECTIVE;
	 *    cap_data.data[0].permitted = (uint32_t) (capabilities & 0xffffffff);
	 *    cap_data.data[0].inheritable = 0;
	 *    cap_data.data[1].permitted = (uint32_t) (capabilities >> 32);
	 *    cap_data.data[1].inheritable = 0;
	 */
	if (capabilities) {
		uint64_t cap_data = ((uint64_t)capabilities->data[1].permitted << 32) + capabilities->data[0].permitted;
		fprintf(fp, "  capabilities=%lu", cap_data);
	}
	fprintf(fp, "\n");
}

int mkdir_recursive(const char *pathname, mode_t mode)
{
	char buf[1024];
	const char *slash;
	const char *p = pathname;
	int width;
	int ret;
	struct stat info;

	while ((slash = strchr(p, '/')) != NULL) {
		width = slash - pathname;
		p = slash + 1;
		if (width < 0)
			break;
		if (width == 0)
			continue;
		if ((unsigned int)width > sizeof(buf) - 1) {
			fprintf(stderr, "path too long for mkdir_recursive\n");
			return -1;
		}
		memcpy(buf, pathname, width);
		buf[width] = 0;
		if (stat(buf, &info) != 0) {
			ret = mkdir(buf, mode);
			if (ret && errno != EEXIST)
				return ret;
		}
	}
	ret = mkdir(pathname, mode);
	if (ret && errno != EEXIST)
		return ret;
	return 0;
}

static char *get_inline_symlink(ext2_ino_t inode_num, struct ext2_inode *inode)
{
	char *symlink_dest = NULL;
	errcode_t retval;
	char *buf = NULL;
	size_t size;

	retval = ext2fs_inline_data_size(fs, inode_num, &size);
	if (retval)
		goto out;

	retval = ext2fs_get_memzero(size + 1, &buf);
	if (retval)
		goto out;

	retval = ext2fs_inline_data_get(fs, inode_num,
					inode, buf, &size);
	if (retval)
		goto out;

	symlink_dest = strdup(buf);

out:
	if (buf)
		ext2fs_free_mem(&buf);
	if (retval)
		com_err(__func__, retval, "while dumping link destination");

	return symlink_dest;
}


void extract_file(ls_file_t *info, int options)
{
	if (info->entry == DIRENT_DELETED_FILE || info->inode_num == 0)
		return; // nothing

	if ((options & EXCL_DIR_OPT) && LINUX_S_ISDIR(info->inode.i_mode))
		return;
	if ((options & EXCL_LNK_OPT) && LINUX_S_ISLNK(info->inode.i_mode))
		return;
	if ((options & EXCL_REG_OPT) && LINUX_S_ISREG(info->inode.i_mode))
		return;

	struct vfs_cap_data *capabilities = (struct vfs_cap_data *)read_xattr(info->inode_num, "security." XATTR_CAPS_SUFFIX);

	if ((options & EXCL_NONCAPS_OPT) && !capabilities)
		return;

	char *selinux_context = (char *)read_xattr(info->inode_num, "security." XATTR_SELINUX_SUFFIX);
	char *symlink_dest = NULL;

	if (LINUX_S_ISLNK(info->inode.i_mode)) {
		if (ext2fs_is_fast_symlink(&(info->inode))) {
			/* Fast symlinks, target stored in inode */
			symlink_dest = strdup((char *)info->inode.i_block);
		}
		else if (info->inode.i_flags & EXT4_INLINE_DATA_FL) {
			/* An inline data symlink */
			symlink_dest = get_inline_symlink(info->inode_num, &(info->inode));
		}
		else {
			/* Slow symlinks, target stored in the first block */
			int retval;
			ext2_file_t infile;
			ext2_off_t wanted;
			unsigned int got;

			if ((retval = ext2fs_file_open(fs, info->inode_num, 0, &infile))) {
				fputs(error_message(retval), stderr);
			}
			else {
				wanted = ext2fs_file_get_size(infile);
				if (wanted > 0) {
					symlink_dest = malloc(wanted);
					if (symlink_dest) {
						if ((retval = ext2fs_file_read(infile, symlink_dest, wanted, &got)))
							fputs(error_message(retval), stderr);
					}
				}
				if ((retval = ext2fs_file_close(infile)))
					fputs(error_message(retval), stderr);
			}
		}
	}

	if (extract_path) {
		char outfile[1024];
		strcpy(outfile, extract_path);
		if (outfile[strlen(outfile)] != '/')
			strcat(outfile, "/");
		strcat(outfile, info->full_name);

		if (extract_path && LINUX_S_ISDIR(info->inode.i_mode)) {
			// make the dir
			mkdir_recursive(outfile, 0755);
		}
		else if (LINUX_S_ISREG(info->inode.i_mode)) {
			// extract file
			int keep = 0;

			int dest = open(outfile, O_CREAT | O_WRONLY | O_TRUNC, 0644);
			if (dest >= 0) {
				/* get the data from the ext2fs */
				int retval = retrieve_data(fs, info->inode_num, dest, outfile, keep, 0, NULL);
				close(dest);
				if (retval) {
					fprintf(stderr, "Error extracting '%s': %s\n", info->full_name, error_message(retval));
					unlink(outfile);
				}
			}
			else
				perror(outfile);
		}
	}

	if (fp_file_contexts && selinux_context) {
		// append file_contexts
		fprintf_file_contexts_entry(fp_file_contexts, info, selinux_context);
	}

	if (fp_C_fs_config) {
		// append C_fs_config
		fprintf_fs_config_entry(fp_C_fs_config, info, capabilities);
	}

	if (fp_X_fs_config && capabilities) {
		// append X_fs_config
		fprintf_fs_config_entry(fp_X_fs_config, info, capabilities);
	}

	if (fp_symlinks && symlink_dest) {
		// append sym_links
		fprintf_symlink_entry(fp_symlinks, info, symlink_dest);
	}

	if (fp_D_listing) {
		fprintf_long_disp(fp_D_listing, info, selinux_context, capabilities, symlink_dest, options);
	}

	if (symlink_dest)
		free(symlink_dest);
	if (selinux_context)
		free(selinux_context);
	if (capabilities)
		free(capabilities);
}

/* Name:    long_disp()
 *
 * Description:
 *
 * This function displays a file's information for a long listing
 *
 * Algorithm:
 *
 * Generate the time string for the modification time
 * Display the file's permission bits, owner, group, mod time, and name
 *
 * Global Variables:
 *
 * none
 *
 * Arguments:
 *
 * ls_file_t *info;             The structure containing the file information
 * int *col;                    The current column - unused
 * int options;                 Options to ls
 *
 * Return Values:
 *
 * None
 *
 * Author: Keith W. Sheffield
 * Date:   06/03/2002
 *
 * Modification History:
 *
 * MM/DD/YY      Name               Description
 * 06/06/02      K.Sheffield        Increased file size width
 * 04/06/04      K.Sheffield        Modified to show entries with an inode of 0
 *                                  as deleted.
 */
void fprintf_long_disp(FILE *fp, ls_file_t *info, const char *selinux_context, struct vfs_cap_data *capabilities, char *symlink_dest, int options)
{
	char lbr, rbr;
	char modestr[11];
	char userstr[9];
	char groupstr[9];
	char datestr[80];
	time_t modtime;
	struct tm *tm_p;


	if (info->entry == DIRENT_DELETED_FILE || info->inode_num == 0) {
		lbr = '>';
		rbr = '<';
	}
	else {
		lbr = rbr = ' ';
	}

	sprintf(modestr, "%c%c%c%c%c%c%c%c%c%c",
	                 LINUX_S_ISLNK(info->inode.i_mode) ? 'l' :
	                 LINUX_S_ISDIR(info->inode.i_mode) ? 'd' :
	                 LINUX_S_ISCHR(info->inode.i_mode) ? 'c' :
	                 LINUX_S_ISBLK(info->inode.i_mode) ? 'b' :
	                 LINUX_S_ISFIFO(info->inode.i_mode) ? 'p' :
	                 LINUX_S_ISSOCK(info->inode.i_mode) ? 's' : '-',
	                 (info->inode.i_mode & (1 << 8)) ? 'r' : '-',
	                 (info->inode.i_mode & (1 << 7)) ? 'w' : '-',
	                 (info->inode.i_mode & LINUX_S_ISUID) ? 'S' :
	                 (info->inode.i_mode & (1 << 6)) ? 'x' : '-',
	                 (info->inode.i_mode & (1 << 5)) ? 'r' : '-',
	                 (info->inode.i_mode & (1 << 4)) ? 'w' : '-',
	                 (info->inode.i_mode & LINUX_S_ISGID) ? 'S' :
	                 (info->inode.i_mode & (1 << 3)) ? 'x' : '-',
	                 (info->inode.i_mode & (1 << 2)) ? 'r' : '-',
	                 (info->inode.i_mode & (1 << 1)) ? 'w' : '-',
	                 (info->inode.i_mode & LINUX_S_ISVTX) ? 'T' :
	                 (info->inode.i_mode & (1 << 0)) ? 'x' : '-');

	if (info->inode_num) {
		if (options & CREATE_OPT)
			modtime = info->inode.i_ctime;
		else
			modtime = info->inode.i_mtime;
		tm_p = localtime(&modtime);
		sprintf(datestr, "%2d-%s-%4d %02d:%02d",
	                     tm_p->tm_mday, monstr[tm_p->tm_mon],
	                     1900 + tm_p->tm_year, tm_p->tm_hour,
	                     tm_p->tm_min);
	}
	else
		strcpy(datestr, "                 ");

	if (options & NUMERIC_OPT) {
		const int userlen = 5;

		sprintf(userstr, "%*d", userlen, info->inode.i_uid);
		sprintf(groupstr, "%*d", userlen, info->inode.i_gid);
	}
#if 0
// always use numeric format from above
	else {
		const int userlen = 8;
		char buf[1024];
		struct passwd pwd, *p_pwd;
		struct group grp, *p_grp;

		getpwuid_r(info->inode.i_uid, &pwd, buf, sizeof(buf), &p_pwd);
		if (p_pwd)
			snprintf(userstr, userlen+1, "%*s", userlen, pwd.pw_name);
		else
			sprintf(userstr, "%*d", userlen, info->inode.i_uid);

		getgrgid_r(info->inode.i_gid, &grp, buf, sizeof(buf), &p_grp);
		if (p_grp)
			snprintf(groupstr, userlen+1, "%*s", userlen, grp.gr_name);
		else
			sprintf(groupstr, "%*d", userlen, info->inode.i_gid);
	}
#endif

	fprintf(fp, "%c%6u%c %10s %s %s  ", lbr, info->inode_num, rbr, modestr, userstr, groupstr);

	if (selinux_context) {
		fprintf(fp, "%-40s  ", selinux_context);
	}

	if (LINUX_S_ISDIR(info->inode.i_mode))
		fprintf(fp, "%9d", info->inode.i_size);
	else
		fprintf(fp, "%9" PRIu64, (uint64_t)(info->inode.i_size | ((__u64)info->inode.i_size_high << 32)));
	fprintf(fp, "  %s", datestr);

	fprintf(fp, "  /%s", info->full_name);

	if (symlink_dest) {
		fprintf(fp, " -> %s", symlink_dest);
	}

	if (capabilities) {
		uint64_t cap_data = ((uint64_t)capabilities->data[1].permitted << 32) + capabilities->data[0].permitted;
		fprintf(fp, "  (capabilities=0x%lx)", cap_data);
	}
	fprintf(fp, "\n");
} /* end of long_disp */

int full_name_sort(const void *n1, const void *n2)
{
	ls_file_t *f1 = *((ls_file_t **) n1);
	ls_file_t *f2 = *((ls_file_t **) n2);

	return(strcmp(f1->full_name, f2->full_name));
}

/* Name:    remove_ls_dups()
 *
 * Description:
 *
 * This function will remove the first directory node if it is the only one
 * found.  It will also remove bogus entries.
 *
 * Algorithm:
 *
 * For each node in the linked list
 *     If the current node has no data
 *        Remove it from the linked list
 *     If the current entry is a DIRECTORY_TYPE
 *        Increment the number of directories.
 * Return the starting node in the linked list
 *
 * Global Variables:
 *
 * None.
 *
 * Arguments:
 *
 * elist *list;                 The linked list to process
 *
 * Return Values:
 *
 * The starting node in the linked list.
 *
 * Author: Keith W. Sheffield
 * Date:   06/05/2002
 *
 * Modification History:
 *
 * MM/DD/YY      Name               Description
 * 04/06/04      K.Sheffield        Modified to just remove the first directory
 *                                  node if it is the only one found.
 *
 */
elist_t * remove_ls_dups(elist_t *list)
{
	elist_t *start = list;
	ls_file_t *cd;
	int cnt=0;

	while(list != NULL) {
		cd = (ls_file_t *) list->data;
		if (cd == NULL) {
			/* remove any empty nodes */
			if (list == start)
				start = list->next;
			list = elist_delete(list, free_ls_file_t);
			continue;
		}
		else if (cd->type == DIRECTORY_TYPE) {
			cnt++;
		}
		list = list->next;
	}

	/* if there is only one directory entry, delete it */
	if (cnt == 1)
		start = elist_delete(start, free_ls_file_t);

	return(start);

} /* end of remove_ls_dups */
