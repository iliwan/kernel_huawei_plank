#include <linux/fs.h>
#include <linux/syscalls.h>
#include <linux/rtc.h>

enum CRITIC_ERRLOG_TYPE {
	TIMER_INIT_ERR = 0,
	SEB_GET_LCS_ERR,
	SEB_READOTP_ERR,
	SEB_LCS_DEF_ERR,
	SEB_RETURN_ERR,
	EMMC_READ_VRL_ERR,
	EMMC_READ_FASTBOOT_ERR,
	EMMC_INIT_ERR,
	EMMC_READ_ERR,
	VRL_CHK_ERR,
	VRL_PARSER_ERR,
	CHGSTORE_ADDR_ERR,
	FASTBOOT_VERF_ERR,
	EFUSEPRELOAD_ERR,
	SECBOOT_GET_LCS_ERR,
	DDR_DETECTED_ERR,
	DDR_DENSITY_ERR,
	CRITIC_MAX_ERR
};

struct event {
	char name[16];
	char args[5][16];
};

struct ERRLOG_INFO{
  unsigned int err_num;
  char * err_str;
 };

enum {
	RESET_MOUNT_FAIL,
	RESET_APANIC,
	RESET_WATCHDOG,
	RESET_PRESS1,
	RESET_PRESS10,
	RESET_ABNORMAL,
	RESET_SMPL,
	RESET_MAX
} reset_types;

enum {
	PMU_SMPL,
	PMU_OVER_VOLT,
	PMU_BATT_IN,
	PMU_RESET,
	PMU_OVER_TEMP,
	PMU_BATT_2V8,
	PMU_BATT_2V3,
	PMU_VSYS_LOW,
	PMU_MAX
} pmu_events;

#define NFF_LOG_FILE     "/splash2/reset_stats"
#define NFF_LOG_FILE_OLD "/splash2/reset_stats.old"
#define MAX_FILE_SIZE     ( 512 * 1024 )
#define INVALID_ARGS     "INVALID_ARGS"
#define INVALID_U32      0x89748974

struct ERRLOG_INFO err_info_arr[] = {
		{TIMER_INIT_ERR, "timer init"},
		{SEB_GET_LCS_ERR, "seb get lcs"},
		{SEB_READOTP_ERR, "seb read otp"},
		{SEB_LCS_DEF_ERR, "seb lcs define"},
		{SEB_RETURN_ERR,	"seb return err"},
		{EMMC_READ_VRL_ERR, "read vrl"},
		{EMMC_READ_FASTBOOT_ERR, "read fastboot"},
		{EMMC_INIT_ERR, "emmc init"},
		{EMMC_READ_ERR, "emmc read"},
		{VRL_CHK_ERR, "vrl check"},
		{VRL_PARSER_ERR, "vrl parse"},
		{CHGSTORE_ADDR_ERR, "chgstore addr"},
		{FASTBOOT_VERF_ERR, "fastboot veryf"},
		{EFUSEPRELOAD_ERR, "efuse prelad"},
		{SECBOOT_GET_LCS_ERR, "secboot get lcs"},
		{DDR_DETECTED_ERR, "ddr detected"},
		{DDR_DENSITY_ERR, "ddr density"}
 
	};


char *func_str[] =	{
	"NO_ERROR",
	"EMMC_INIT",
	"BOARDID_INIT",
	"SELECT_HW_CONFIG",
	"PROCESS_MODE",
	"LOAD_M3",
	"LOAD_MODEM",
	"LOAD_TEEOS",
	"LOAD_HIFI",
	"LOAD_BBE16",
	"LOAD_KERNEL",
	"LOAD_RECOVERY",
	"BOOT_KERNEL",
	"BOOT_RECOVERY",
	"LOAD_IOM3",
	"LOAD_BL31",
	"LOAD_LPM3",
	"GET_BATT_TEMP",
	"PANIC",
	"MAX_ERROR",
};

#define NFF_EVENT_INIT(event)                                             \
	do {                                                                  \
		memset(&event, 0, sizeof(event));                                 \
		strncpy(event.name,    INVALID_ARGS, sizeof(event.name)    - 1);  \
		strncpy(event.args[0], INVALID_ARGS, sizeof(event.args[0]) - 1);  \
		strncpy(event.args[1], INVALID_ARGS, sizeof(event.args[1]) - 1);  \
		strncpy(event.args[2], INVALID_ARGS, sizeof(event.args[2]) - 1);  \
		strncpy(event.args[3], INVALID_ARGS, sizeof(event.args[3]) - 1);  \
		strncpy(event.args[4], INVALID_ARGS, sizeof(event.args[4]) - 1);  \
	} while(0)

int reset_type = RESET_MAX;
int pmu_event = PMU_MAX;

static DEFINE_MUTEX(nff_log_mutex);

static int __init early_parse_reset_type_cmdline(char *p)
{
	if (p) {
		if (!strcmp(p, "MountFail")) {
			reset_type = RESET_MOUNT_FAIL;
		} else if (!strcmp(p, "PanicReset")) {
			reset_type = RESET_APANIC;
		} else if (!strcmp(p, "WatchDog")) {
			reset_type = RESET_WATCHDOG;
		} else if (!strcmp(p, "press1s")) {
			reset_type = RESET_PRESS1;
		} else if (!strcmp(p, "press10s")) {
			reset_type = RESET_PRESS10;
		} else if (!strcmp(p, "AbnormalReset")) {
			reset_type = RESET_ABNORMAL;
		} else if (!strcmp(p, "SMPL")) {
			reset_type = RESET_SMPL;
		}
    }

    return 0;
}
early_param("normal_reset_type", early_parse_reset_type_cmdline);

static int __init early_parse_pmu_event_cmdline(char *p)
{
	if (p) {
		if (!strcmp(p, "SMPL")) {
			pmu_event = PMU_SMPL;
		} else if (!strcmp(p, "OVER")) {     /* OVER VOLT */
			pmu_event = PMU_OVER_VOLT;
		} else if (!strcmp(p, "RESET")) {
			pmu_event = PMU_RESET;
		} else if (!strcmp(p, "Over")) {     /* Over TEMP */
			pmu_event = PMU_OVER_TEMP;
		} else if (!strcmp(p, "BATT")) {
			if (!strncmp(p+strlen("BATT "), "IN", strlen("IN")))
				pmu_event = PMU_BATT_IN;
			else if (!strncmp(p + strlen("BATT "), "2V8", strlen("2V8")))
				pmu_event = PMU_BATT_2V8;
			else if (!strncmp(p + strlen("BATT "), "2V3", strlen("2V3")))
				pmu_event = PMU_BATT_2V3;
		} else if (!strcmp(p, "VSYS_LOW")) {
			pmu_event = PMU_VSYS_LOW;
		}
    }

    return 0;
}
early_param("pmu_event", early_parse_pmu_event_cmdline);

static void get_current_time(char *ts, unsigned int len)
{
	struct timeval tv;
	struct timespec now;
	struct rtc_time tm;

	if(!ts) {
	   return;
	}

	memset(&tv, 0, sizeof(struct timeval));
	memset(&tm, 0, sizeof(struct rtc_time));

	do_gettimeofday(&tv);
	tv.tv_sec -= sys_tz.tz_minuteswest * 60;
	rtc_time_to_tm(tv.tv_sec, &tm);

	snprintf(ts, len, "%04d-%02d-%02d %02d:%02d:%02d",
		tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
		tm.tm_hour, tm.tm_min, tm.tm_sec);
}

static int nff_log_event(struct event* event)
{
	int fd = -1;
	int ret = 0;
	int i = 0;
	struct stat statbuf = {0};
	char buf[128] = {0};
	char local_time[20] = {0};
	mm_segment_t old_fs;

	if (!event)
		return -1;

	if (!strncmp(event->name, INVALID_ARGS, strlen(INVALID_ARGS)))
		return -1;

	old_fs = get_fs();
	set_fs(KERNEL_DS);

	if (sys_newstat(NFF_LOG_FILE, &statbuf) < 0) {
		pr_err("<%s: %d>, stat failed! ret = %d\n", __func__, __LINE__, ret);
	} else {
		if (statbuf.st_size >= MAX_FILE_SIZE) {
			if (sys_rename(NFF_LOG_FILE, NFF_LOG_FILE_OLD) < 0) {
				pr_err("<%s: %d>, rename failed! ret = %d\n", __func__, __LINE__, ret);
				set_fs(old_fs);
				return -1;
			}
		}
	}

	if (sys_access(NFF_LOG_FILE, 0)) {
		fd = sys_open(NFF_LOG_FILE, O_CREAT | O_RDWR, 0664);  /* create file */
		if (fd < 0) {
			pr_err("<%s: %d>, create open failed, ret = %d\n", __func__, __LINE__, fd);
			set_fs(old_fs);
			return -1;
		}
		memset(buf, 0, sizeof(buf));
		strncat(buf, "     DATE & TIME              EVENT | DETAILS\n", sizeof(buf));
		sys_write(fd, buf, strlen(buf));
	} else {
		fd = sys_open(NFF_LOG_FILE, O_APPEND | O_RDWR, 0664);  /* append in the end */
		if (fd < 0) {
			pr_err("<%s: %d>, append open failed, ret = %d\n", __func__, __LINE__, fd);
			set_fs(old_fs);
			return -1;
		}
	}

	memset(buf, 0, sizeof(buf));
	get_current_time(local_time, sizeof(local_time));
	strncat(buf, local_time,  sizeof(buf) - 1);
	strncat(buf, " ",         sizeof(buf) - strlen(buf) - 1);
	strncat(buf, event->name, sizeof(buf) - strlen(buf) - 1);
	strncat(buf, " | ",       sizeof(buf) - strlen(buf) - 1);

	for (i = 0; i < 5; i++) {
		if (strncmp(event->args[i], INVALID_ARGS, strlen(INVALID_ARGS))) {
			printk("event->args[%d] = %s\n", i, event->args[i]);
			strncat(buf, event->args[i], sizeof(buf) - strlen(buf) -1);
			strncat(buf, " ",            sizeof(buf) - strlen(buf) -1);
		}
	}

	strncat(buf, "\n", sizeof(buf) - strlen(buf) - 1);

	sys_write(fd, buf, strlen(buf));

	sys_close(fd);
	set_fs(old_fs);

	return 0;
}

void nff_log_event_hungtask(char *taskname)
{
	struct event hungtask_event;

	if(!taskname)
		return;

	NFF_EVENT_INIT(hungtask_event);

	snprintf(hungtask_event.name,    sizeof(hungtask_event.name),    "%15s", "HUNGTASK");
	snprintf(hungtask_event.args[0], sizeof(hungtask_event.args[0]), "%-15s", taskname);

	mutex_lock(&nff_log_mutex);
	nff_log_event(&hungtask_event);
	mutex_unlock(&nff_log_mutex);
}

void nff_log_event_hungtask_test(void)
{
	nff_log_event_hungtask(current->comm);
}

void nff_log_event_ocp(char *ldo)
{
	struct event ocp_event;

	if(!ldo)
		return;

	NFF_EVENT_INIT(ocp_event);

	snprintf(ocp_event.name,    sizeof(ocp_event.name),    "%15s", "OCP");
	snprintf(ocp_event.args[0], sizeof(ocp_event.args[0]), "%-15s", ldo);

	mutex_lock(&nff_log_mutex);
	nff_log_event(&ocp_event);
	mutex_unlock(&nff_log_mutex);
}

void nff_log_event_ocp_test(void)
{
	nff_log_event_ocp("LDO16(test)");
}

void nff_log_event_ddrc(unsigned int port, unsigned int mid, bool rw, bool pri, bool sec)
{
	struct event ddrc_event;

	NFF_EVENT_INIT(ddrc_event);

	snprintf(ddrc_event.name,    sizeof(ddrc_event.name)   , "%15s", "DDRC");
	snprintf(ddrc_event.args[0], sizeof(ddrc_event.args[0]), "%-6s%-#9x", "Port: ", port);
	snprintf(ddrc_event.args[1], sizeof(ddrc_event.args[1]), "%-6s%-#9x", "Mid: ", mid);
	snprintf(ddrc_event.args[2], sizeof(ddrc_event.args[2]), "%-15s", rw  ? "Ops: Read" : "Ops: Write");
	snprintf(ddrc_event.args[3], sizeof(ddrc_event.args[3]), "%-15s", pri ? "Privileged" : "Unprivileged");
	snprintf(ddrc_event.args[4], sizeof(ddrc_event.args[4]), "%-15s", sec ? "Secure" : "Non-Secure");

	mutex_lock(&nff_log_mutex);
	nff_log_event(&ddrc_event);
	mutex_unlock(&nff_log_mutex);
}

void nff_log_event_ddrc_test(void)
{
	nff_log_event_ddrc(0x2, 0x31, 0, 0, 0);
}


void nff_log_event_subsys_err(unsigned int mod_id, unsigned int arg1,
				unsigned int arg2, unsigned int arg3)
{
	struct event ss_event;

	NFF_EVENT_INIT(ss_event);

	snprintf(ss_event.name,    sizeof(ss_event.name),    "%15s",     "SUBSYS_CRASH");
	snprintf(ss_event.args[0], sizeof(ss_event.args[0]), "%-15.08x", mod_id);
	if (arg1 != INVALID_U32)
		snprintf(ss_event.args[1], sizeof(ss_event.args[1]), "%-#15.08x", arg1);
	if (arg2 != INVALID_U32)
		snprintf(ss_event.args[2], sizeof(ss_event.args[2]), "%-#15.08x", arg2);
	if (arg3 != INVALID_U32)
		snprintf(ss_event.args[3], sizeof(ss_event.args[3]), "%-#15.08x", arg3);

	mutex_lock(&nff_log_mutex);
	nff_log_event(&ss_event);
	mutex_unlock(&nff_log_mutex);
}


void nff_log_event_subsys_err_test(void)
{
	nff_log_event_subsys_err(0x82000001, 0x20b, 0x93, 0x35229e38);
}


void nff_log_event_reset(void)
{
	struct event reset_event;

	NFF_EVENT_INIT(reset_event);

	printk("nff_log_event: reset_type = %d, pmu_event = %d\n", reset_type, pmu_event);
	switch(reset_type) {
		case RESET_MOUNT_FAIL:
			snprintf(reset_event.name, sizeof(reset_event.name), "%15s", "MOUNT_FAIL");
			break;
		case RESET_APANIC:
			snprintf(reset_event.name, sizeof(reset_event.name), "%15s", "APANIC");
			break;
		case RESET_WATCHDOG:
			snprintf(reset_event.name, sizeof(reset_event.name), "%15s", "WATCHDOG");
			break;
		case RESET_PRESS10:
			snprintf(reset_event.name, sizeof(reset_event.name), "%15s", "PRESS10");
			break;
		case RESET_ABNORMAL:
			snprintf(reset_event.name, sizeof(reset_event.name), "%15s", "ABNORMAL_RESET");
			break;
		case RESET_SMPL:
			snprintf(reset_event.name, sizeof(reset_event.name), "%15s", "SMPL");
			break;
		default:
			break;
	}

	switch(pmu_event) {
		case PMU_SMPL:
			snprintf(reset_event.args[0], sizeof(reset_event.args[0]), "%-15s", "SMPL");
			break;
		case PMU_OVER_VOLT:
			snprintf(reset_event.args[0], sizeof(reset_event.args[0]), "%-15s", "OVER_VOLT");
			break;
		case PMU_BATT_IN:
			snprintf(reset_event.args[0], sizeof(reset_event.args[0]), "%-15s", "BATT_IN");
			if (reset_type == RESET_PRESS1)
				snprintf(reset_event.name, sizeof(reset_event.name),   "%15s",  "PRESS10");
			break;
		case PMU_OVER_TEMP:
			snprintf(reset_event.args[0], sizeof(reset_event.args[0]), "%-15s", "OVER_TEMP");
			break;
		case PMU_BATT_2V8:
			snprintf(reset_event.args[0], sizeof(reset_event.args[0]), "%-15s", "BATT_2V8");
			break;
		case PMU_BATT_2V3:
			snprintf(reset_event.args[0], sizeof(reset_event.args[0]), "%-15s", "BATT_2V3");
			break;
		case PMU_VSYS_LOW:
			if (reset_type == RESET_ABNORMAL)
				snprintf(reset_event.args[0], sizeof(reset_event.args[0]), "%-15s", "VSYS_LOW");
			break;
		default:
			break;
	}

	/* if reset_type is null but pmu_evnet is not null, this is abnormal reset */
	if (!strncmp(reset_event.name, INVALID_ARGS, strlen(INVALID_ARGS))
	  && strncmp(reset_event.args[0], INVALID_ARGS, strlen(INVALID_ARGS))) {
		snprintf(reset_event.name, sizeof(reset_event.name), "%15s", "ABNORMAL_RESET");
	}

	mutex_lock(&nff_log_mutex);
	nff_log_event(&reset_event);
	mutex_unlock(&nff_log_mutex);
}
int nff_log_errlog(unsigned int err_num)
{
	struct event errlog_event;
	int ret;
	if (err_num > CRITIC_MAX_ERR)
		return 0;
	NFF_EVENT_INIT(errlog_event);
	snprintf(errlog_event.name, sizeof(errlog_event.name), "%15s", "ERRLOG");
	snprintf(errlog_event.args[0], sizeof(errlog_event.args[0]), "%-15s", err_info_arr[err_num].err_str);
	mutex_lock(&nff_log_mutex);
	ret = nff_log_event(&errlog_event);
	mutex_unlock(&nff_log_mutex);
	return ret;
}

int nff_log_funerr(unsigned int func_num, unsigned int err_num)
{
	struct event fun_event;
	int ret;
	NFF_EVENT_INIT(fun_event);
	snprintf(fun_event.name, sizeof(fun_event.name), "%15s", "FUNERR");
	snprintf(fun_event.args[0], sizeof(fun_event.args[0]), "%-15s", func_str[func_num]);
	snprintf(fun_event.args[1], sizeof(fun_event.args[1]), "%04x", err_num);
	mutex_lock(&nff_log_mutex);
	ret = nff_log_event(&fun_event);
	mutex_unlock(&nff_log_mutex);
	return ret;
}
