/* Generated from the registered service vocabulary. */
static const struct {
  const char *domain;
  int group;
} rf_domains[] = {
    {"xiaohongshu.com", 0}, {"xhscdn.com", 0},      {"csdn.net", 1},
    {"csdn.com", 1},        {"baidu.com", 2},       {"bdstatic.com", 2},
    {"bcebos.com", 2},      {"weibo.com", 3},       {"weibo.cn", 3},
    {"sinaimg.cn", 3},      {"bilibili.com", 4},    {"bilivideo.com", 4},
    {"iqiyi.com", 5},       {"qiyi.com", 5},        {"youtube.com", 6},
    {"googlevideo.com", 6}, {"ytimg.com", 6},       {"douyin.com", 7},
    {"kuaishou.com", 8},    {"gifshow.com", 8},     {"ksapisrv.com", 8},
    {"kwimgs.com", 8},      {"kwaicdn.com", 8},     {"kuaishouzt.com", 8},
    {"tiktok.com", 9},      {"douyu.com", 10},      {"douyucdn.cn", 10},
    {"huya.com", 11},       {"msstatic.com", 11},   {"twitch.tv", 12},
    {"twitchcdn.net", 12},  {"jtvnw.net", 12},      {"ttvnw.net", 12},
    {"y.qq.com", 13},       {"qqmusic.qq.com", 13}, {"aqqmusic.tc.qq.com", 13},
    {"music.163.com", 14},  {"music.126.net", 14},  {"spotify.com", 15},
    {"scdn.co", 15},
};
static const struct {
  const char *domain;
  int group;
} rf_role_domains[] = {
    {"bilivideo.com", 17},      {"googlevideo.com", 17}, {"music.126.net", 19},
    {"aqqmusic.tc.qq.com", 19}, {"scdn.co", 19},
};
static const char *rf_role_patterns[] = {
    "(^|[.-])(search|recommend|recommendation|rec|feed|article|news|web|image["
    "0-9]*|img[0-9]*|pic[0-9]*|cover|thumb)([.-]|$)",
    "(^|[.-])(video[0-9]*|vod|player|playurl)([.-]|$)",
    "(^|[.-])(live[0-9]*|broadcast)([.-]|$)",
    "(^|[.-])(audio[0-9]*|music|song)([.-]|$)",
    "(^|[.-])(api[0-9]*|interface[0-9]*|gateway|graphql|httpdns)([.-]|$)",
    "(^|[.-])(ulog|log|logs|stat[0-9]*|report|analytics|metrics|telemetry)([.-]"
    "|$)",
};
