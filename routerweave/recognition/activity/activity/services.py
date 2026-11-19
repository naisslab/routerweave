"""Map passive names to the service vocabulary used for fitting."""

from functools import lru_cache
import re

OWNER_DOMAINS = (
    ("xiaohongshu.com", "xhscdn.com",),
    ("csdn.net", "csdn.com",),
    ("baidu.com", "bdstatic.com", "bcebos.com",),
    ("weibo.com", "weibo.cn", "sinaimg.cn",),
    ("bilibili.com", "bilivideo.com",),
    ("iqiyi.com", "qiyi.com",),
    ("youtube.com", "googlevideo.com", "ytimg.com",),
    ("douyin.com",),
    ("kuaishou.com", "gifshow.com", "ksapisrv.com", "kwimgs.com", "kwaicdn.com", "kuaishouzt.com",),
    ("tiktok.com",),
    ("douyu.com", "douyucdn.cn",),
    ("huya.com", "msstatic.com",),
    ("twitch.tv", "twitchcdn.net", "jtvnw.net", "ttvnw.net",),
    ("y.qq.com", "qqmusic.qq.com", "aqqmusic.tc.qq.com",),
    ("music.163.com", "music.126.net",),
    ("spotify.com", "scdn.co",),
)
ROLE_DOMAINS = {
    "bilivideo.com": 17,
    "googlevideo.com": 17,
    "music.126.net": 19,
    "aqqmusic.tc.qq.com": 19,
    "scdn.co": 19,
}
ROLE_PATTERNS = tuple(map(re.compile, (
    r"(^|[.-])(search|recommend|recommendation|rec|feed|article|news|web|image[0-9]*|img[0-9]*|pic[0-9]*|cover|thumb)([.-]|$)",
    r"(^|[.-])(video[0-9]*|vod|player|playurl)([.-]|$)",
    r"(^|[.-])(live[0-9]*|broadcast)([.-]|$)",
    r"(^|[.-])(audio[0-9]*|music|song)([.-]|$)",
    r"(^|[.-])(api[0-9]*|interface[0-9]*|gateway|graphql|httpdns)([.-]|$)",
    r"(^|[.-])(ulog|log|logs|stat[0-9]*|report|analytics|metrics|telemetry)([.-]|$)",
)))
MIME_GROUPS = {"audio": 22, "video": 23, "image": 24, "api": 25, "text": 26}
OWNER_MASK = (1 << 16) - 1
ROLE_MASK = ((1 << 6) - 1) << 16


@lru_cache(maxsize=8192)
def name_bits(name):
    labels = name.lower().rstrip(".").split(".")
    suffixes = {".".join(labels[i:]) for i in range(len(labels))}
    bits = 0
    longest = 0
    for slot, domains in enumerate(OWNER_DOMAINS):
        for domain in domains:
            if domain in suffixes:
                bits |= 1 << slot
                longest = max(longest, len(domain))
    host = ".".join(labels)
    prefix = host[:-longest].rstrip(".") if longest else host
    for slot, pattern in enumerate(ROLE_PATTERNS, start=16):
        if pattern.search(prefix):
            bits |= 1 << slot
    for domain, slot in ROLE_DOMAINS.items():
        if domain in suffixes:
            bits |= 1 << slot
    return bits


def combined_bits(names):
    bits = 0
    for name in names:
        bits |= name_bits(name)
    return bits


def associate(connection, candidates):
    direct = connection.hosts
    groups = ([(name,) for names in direct.values() for name in names]
              if direct else candidates)
    owners = roles = 0
    unknown = False
    for names in groups:
        bits = combined_bits(names)
        owners |= bits & OWNER_MASK
        roles |= bits & ROLE_MASK
        unknown |= not bool(bits & OWNER_MASK)
    ambiguous = owners.bit_count() > 1 or bool(owners and unknown)
    if ambiguous:
        owners = 0
    mime = 1 << MIME_GROUPS[connection.media] if connection.media else 0
    quality = (bool(candidates), bool(direct.get("tls")), bool(direct.get("http")),
               bool(groups and not owners and not ambiguous), not groups,
               ambiguous, bool(roles), bool(mime))
    return owners | roles | mime, quality
