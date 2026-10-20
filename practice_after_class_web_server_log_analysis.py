import argparse
import json
import os
import re
from datetime import datetime


def file_analysis(file_name):
    with open(file_name, "r", encoding="UTF-8") as file:
        pattern = re.compile(
                r'^(?P<host>\S+) '
                r'\S+ \S+ '
                r'\[(?P<time>[^\]]+)\] ' 
                r'"(?P<request>.*?)" '
                r'(?P<status>\d+) ' 
                r'(?P<bytes>\d+|-) ' 
                r'"(?P<referer>.*?)" '
                r'"(?P<user_agent>.*?)" '
                r'(?P<duration>\d+)$')
        result = {'top_ips': {}, "top_longest": [], 'total_stat': {}, 'total_requests': 0,}
        tmp_top_ips = {}
        tmp_top_longest = []
        for line in file:
            result["total_requests"] += 1
            match = pattern.match(line)
            if match.group("request").split()[0] not in result["total_stat"]:
                result["total_stat"][match.group("request").split()[0]] = 1
            else:
                result["total_stat"][match.group("request").split()[0]] += 1
            if match.group("host") not in tmp_top_ips:
                tmp_top_ips[match.group("host")] = 1
            else:
                tmp_top_ips[match.group("host")] += 1
            if len(tmp_top_longest) < 3:
                tmp_top_longest.append({"ip": match.group("host"),
                                        "date": match.group("time"),
                                        "method": match.group("request").split()[0],
                                        "url": match.group("referer"),
                                        "duration": match.group("duration")})
            else:
                tmp_top_longest = sorted(tmp_top_longest, key=lambda x: int(x["duration"]), reverse=True)
                if int(match.group("duration")) > int(tmp_top_longest[-1]["duration"]):
                    tmp_top_longest[-1] = {"ip": match.group("host"),
                                        "date": match.group("time"),
                                        "method": match.group("request").split()[0],
                                        "url": match.group("referer"),
                                        "duration": match.group("duration")}
        result["top_longest"] = tmp_top_longest
        result["top_ips"] = dict(sorted(tmp_top_ips.items(), key= lambda x: x[1], reverse = True)[0:3])
        save_json(result, file_name)

def save_json(dict_for_save, file_name):
    if "/" in file_name:
        file_name = file_name.split("/")[-1]
    with open(f"{datetime.now().strftime("%d-%m-%Y-%H:%M")}-analysis-{file_name.removesuffix(".log")}-file.json", "w", encoding="utf-8") as file:
        json.dump(dict_for_save, file, ensure_ascii=False, indent=4)
        print(json.dumps(dict_for_save, ensure_ascii=False, indent=4))


parser = argparse.ArgumentParser(description="Скрипт для анализа логов Linux")
parser.add_argument('path', type=str, help='Путь к файлу или директории')


if os.path.isfile(parser.parse_args().path):
    print("Анализ файла:", parser.parse_args().path)
    file_analysis(parser.parse_args().path)
else:
    print("Анализ директории:", parser.parse_args().path)
    for file_name in os.listdir(parser.parse_args().path):
        file_analysis(f"{parser.parse_args().path}{file_name}")