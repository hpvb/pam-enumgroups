#include <security/pam_modules.h>
#include <grp.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>

#define UNUSED __attribute__((__unused__))

PAM_EXTERN int pam_sm_authenticate(pam_handle_t * pamh UNUSED, int flags UNUSED, int argc UNUSED, const char **argv UNUSED) {
	return PAM_IGNORE;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t * pamh, int flags, int argc UNUSED, const char **argv UNUSED) {
	int retval = PAM_SUCCESS;
	struct group *group;
	char **members;
	const char *user;
	int nogroups = 0;
	int alloc_size = 100;
	gid_t *grouplist;

	if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS || user == NULL || *user == '\0') {
		pam_syslog(pamh, LOG_ERR, "cannot determine the user's name");
		return PAM_USER_UNKNOWN;
	}

	grouplist = malloc(alloc_size * sizeof(gid_t *));

	for (group = getgrent(); group != NULL; group = getgrent()) {
		for (members = group->gr_mem; *members != NULL; members++) {
			if (strcmp(user, *members) == 0) {
				grouplist[nogroups] = group->gr_gid;
				nogroups++;

				if (nogroups > alloc_size) {
					alloc_size *= 2;
					grouplist = realloc(grouplist, alloc_size * sizeof(gid_t *));
				}
			}
		}
	}

	if (setgroups(nogroups, grouplist)) {
		pam_syslog(pamh, LOG_ERR, "setgroups for %s failed: %s", user, strerror());
		retval = PAM_CRED_ERR;
	}

	free(grouplist);
	endgrent();
	return retval;
}

