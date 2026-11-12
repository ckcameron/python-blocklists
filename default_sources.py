# Curated sources retained from the original script.
DEFAULT_BLOCKLISTS = [
    # Malware / Threat Intelligence
    (
        "abuse-ch-feodo-ipblocklist",
        "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
    ),
    (
        "abuse-ch-sslbl-ipblocklist",
        "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt",
    ),
    ("abuse-ch-urlhaus-domains", "https://urlhaus.abuse.ch/downloads/text_online/"),
    (
        "emerging-threats-compromised-ips",
        "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
    ),
    (
        "emerging-threats-block-ips",
        "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt",
    ),
    # Ad / Tracking Domains
    (
        "stevenblack-hosts",
        "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    ),
    (
        "peter-lowe-adservers",
        "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=nohtml&showintro=0&mimetype=plaintext",
    ),
    # Phishing / Fraud
    ("openphish-feed", "https://openphish.com/feed.txt"),
    (
        "phishing-army-blocklist",
        "https://phishing.army/download/phishing_army_blocklist.txt",
    ),
    # Mixed IP + Domain
    ("blocklist-de-all", "https://lists.blocklist.de/lists/all.txt"),
    (
        "stamparm-ipsum-level1",
        "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/1.txt",
    ),
    ("cinsscore-badguys", "https://cinsscore.com/list/ci-badguys.txt"),
]
