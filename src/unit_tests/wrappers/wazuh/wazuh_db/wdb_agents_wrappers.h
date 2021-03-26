/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef WDB_AGENTS_WRAPPERS_H
#define WDB_AGENTS_WRAPPERS_H

#include "wazuh_db/wdb.h"

int __wrap_wdb_agents_insert_vuln_cves(wdb_t *wdb, const char* name, const char* version, const char* architecture, const char* cve);
int __wrap_wdb_agents_update_status_vuln_cves(wdb_t *wdb, const char* old_status, const char* new_status);
int __wrap_wdb_agents_remove_vuln_cves(wdb_t *wdb, const char* cve, const char* reference);
wdbc_result __wrap_wdb_agents_remove_by_status_vuln_cves(wdb_t *wdb, const char* status, char **output);
int __wrap_wdb_agents_clear_vuln_cves(wdb_t *wdb);

#endif