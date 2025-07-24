import os
import re
import csv
import json
import time
import shutil
import tempfile
import subprocess
from urllib.parse import urlparse
from datetime import datetime, timezone
import fade

from newspaper import Article, Config
from openai import OpenAI
from dotenv import load_dotenv
from selenium import webdriver
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
from stix2 import (Indicator, Malware, ThreatActor, Report, Relationship, Bundle, Identity, Vulnerability, AttackPattern)

import warnings
from urllib3.exceptions import NotOpenSSLWarning

warnings.filterwarnings("ignore", category=NotOpenSSLWarning)


DOTENV_PATH = '.env'
if os.path.exists(DOTENV_PATH):
    print(f"[*] Loading environment variables from {DOTENV_PATH}")
    load_dotenv(dotenv_path=DOTENV_PATH)
else:
    print(f"[!] Warning: .env file not found at {DOTENV_PATH}.")

try:
    client = OpenAI()
    
    if not client.api_key:
        raise ValueError("OPENAI_API_KEY environment variable is not set.")
except (ValueError, ImportError) as e:
    print(f"[!] FATAL: Could not initialize OpenAI client. Error: {e}")
    exit()
except Exception as e: # Catch other potential init errors
    print(f"[!] FATAL: An unexpected error occurred initializing OpenAI: {e}")
    exit()


SAFE_DOMAINS_PATH = "safe_domains.txt"
PROCESSING_DIR = "analysis/processing_html"


def defang(ioc_string):
    if not isinstance(ioc_string, str):
        return str(ioc_string)
    return ioc_string.replace('http', 'hxxp').replace('.', '[.]')

def load_safe_domains(file_path=SAFE_DOMAINS_PATH):
    if not os.path.exists(file_path): return set()
    with open(file_path, "r") as f: return set(line.strip().lower() for line in f if line.strip())

SAFE_DOMAINS = load_safe_domains()

def is_safe_domain(domain):
    if not domain: return False
    domain = domain.lower()
    return any(domain == d or domain.endswith(f".{d}") for d in SAFE_DOMAINS)

def is_git_repo(url):
    parsed = urlparse(url)
    return "github.com" in parsed.netloc or "gitlab.com" in parsed.netloc or url.endswith(".git")

def clone_and_extract_iocs_from_git(repo_url):
    print(f"[*] Cloning Git repo for deep analysis: {repo_url}")
    temp_dir = tempfile.mkdtemp()
    try:
        # Clone the repo quietly
        subprocess.run(
            ["git", "clone", "--depth=1", repo_url, temp_dir],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        all_text = ""
        for root, _, files in os.walk(temp_dir):
            for file in files:
                if file.endswith(('.png', '.jpg', '.gif', '.zip', '.bin', '.exe')):
                    continue
                try:
                    with open(os.path.join(root, file), "r", errors="ignore") as f:
                        all_text += f.read() + "\n"
                except Exception:
                    pass 
        
        if all_text:
            print("[*] Git repo content aggregated. Sending to OpenAI for analysis...")
            return analyze_text_with_openai(all_text)
        else:
            print("[!] Could not extract any text from the Git repo.")
            return {}
            
    except subprocess.CalledProcessError:
        print(f"[!] Git clone failed for {repo_url}. The repository may be private or deleted.")
        return {}
    except Exception as e:
        print(f"[!] An unexpected error occurred during Git processing for {repo_url}: {e}")
        return {}
    finally:
        shutil.rmtree(temp_dir)


def scrape_dynamic_page_with_selenium(url):
    print(fade.pinkred("[*] Falling back to Selenium for dynamic content..."))
    chrome_options = Options()
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--disable-dev-shm-usage")
    chrome_options.add_argument("user-agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
    try:
        with webdriver.Chrome(service=ChromeService(ChromeDriverManager().install()), options=chrome_options) as driver:
            driver.get(url)
            time.sleep(5) 
            body = driver.find_element(By.TAG_NAME, 'body')
            return body.text
    except Exception as e:
        print(f"[!] Selenium scraping failed for {url}: {e}")
        return None

def scrape_and_save_page(url, output_dir):
    try:
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "Accept-Language": "en-US,en;q=0.9"}
        config = Config()
        config.headers = headers
        config.browser_user_agent = headers['User-Agent']
        config.request_timeout = 15
        
        article = Article(url, config=config)
        article.download()
        article.parse()
        page_text = article.text
        
        if not page_text or page_text.isspace():
            print(fade.fire(f"[!] Newspaper3k failed to extract meaningful text from {url}."))
            page_text = scrape_dynamic_page_with_selenium(url)
            
        if not page_text or page_text.isspace():
            print(f"[!] CRITICAL: All scraping methods failed for {url}.")
            return None
            
        os.makedirs(output_dir, exist_ok=True)
        safe_filename = re.sub(r'[^a-zA-Z0-9_-]', '_', url)[:100] + ".txt" 
        filepath = os.path.join(output_dir, safe_filename)
        with open(filepath, "w", encoding="utf-8") as f:
            title = article.title if article.title else url
            f.write(f"URL: {url}\n\nTITLE: {title}\n\n---\n\n{page_text}")
            
        return page_text
    except Exception as e:
        print(f"[!] An error occurred during article scraping for {url}: {e}")
        return None

def analyze_text_with_openai(text):
    if not text or text.isspace():
        print("[!] Text is empty, skipping OpenAI analysis.")
        return None
        
    prompt = """
    You are an expert threat intelligence analyst on a highly advanced research team. Your task is to meticulously analyze the following text from a cybersecurity research article.
    Extract all potential Indicators of Compromise (IOCs) and other key research artifacts. These artifacts are crucial for another researcher to understand the threat and take action.

    Please extract the following categories:
    - ip_addresses: All IPv4 and IPv6 addresses.
    - domains: Fully qualified domain names (FQDNs).
    - urls: Complete URLs.
    - file_hashes: MD5, SHA1, and SHA256 hashes.
    - email_addresses: Email addresses mentioned.
    - cves: Common Vulnerabilities and Exposures identifiers (e.g., CVE-2023-12345).
    - malware_families: Names of malware families or tools (e.g., Cobalt Strike, Emotet).
    - threat_actors: Names of threat actor groups or campaigns (e.g., APT29, Operation Nightfall).
    - mitre_ttps: MITRE ATT&CK Technique or Sub-technique IDs (e.g., T1059.003, T1566).

    After extraction, provide a "hunting_narrative": a concise, actionable summary for a security analyst. This narrative should explain the threat and provide specific hunting tips based on the extracted artifacts, correlating them where possible.

    **Provide your response in a single, minified JSON object with no markdown formatting.** The JSON object must have these exact keys: "ips", "domains", "urls", "hashes", "emails", "cves", "malware_families", "threat_actors", "mitre_ttps", and "hunting_narrative".
    If no indicators for a category are found, the value must be an empty list []. The narrative must be a single string.

    Analyze this text:
    ---
    """ + text
    
    try:
        print(fade.greenblue("[*] Sending text to OpenAI for IOC extraction..."))
        response = client.chat.completions.create(
            model="gpt-4o",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.0,
            response_format={"type": "json_object"}
        )
        print(fade.brazil("[*] OpenAI IOC extraction complete."))
        return json.loads(response.choices[0].message.content)
    except Exception as e:
        if "authentication" in str(e).lower():
            print("[!] FATAL: OpenAI authentication error. Check your API key.")
            exit()
        print(f"[!] An error occurred during the IOC extraction API call: {e}")
        return None

def generate_summary_and_stix_report(all_iocs, summary_csv_path, stix_path):
    print(fade.brazil("[+] Starting final report generation..."))
    summary_data = "Key Indicators and Artifacts Collected:\n"
    for key, values in all_iocs.items():
        if values:
            summary_data += f"- {key.replace('_', ' ').title()}: {', '.join(sorted(list(values)))}\n"
    
    summary_prompt = f"""
    You are a senior threat intelligence researcher writing a technical summary for your peers.
    Based on the aggregated data, generate a deep technical analysis of the potential threat landscape.
    Your analysis should:
    - Identify and correlate potential patterns across the data (e.g., shared infrastructure, overlapping TTPs).
    - Hypothesize potential threat actor motivations or objectives.
    - Propose concrete, actionable threat hunting leads that a security analyst or peer researcher can use immediately.
    - Mention specific tools or queries (e.g., for Splunk, Grep, YARA) where applicable.

    After extraction, provide a "hunting_narrative": a concise, actionable summary for a security analyst. This narrative should explain the threat and provide specific hunting tips based on the extracted artifacts, correlating them where possible.
    Return a minified JSON object with the key "technical_summary".

    Aggregated Data:
    ---
    {summary_data}
    """
    technical_summary = "Failed to generate summary."
    try:
        print(fade.greenblue("[*] Sending aggregated data to OpenAI for technical summary..."))
        response = client.chat.completions.create(model="gpt-4o", messages=[{"role": "user", "content": summary_prompt}], temperature=0.5, response_format={"type": "json_object"})
        summary_json = json.loads(response.choices[0].message.content)
        technical_summary = summary_json.get("technical_summary", technical_summary)
        print(fade.brazil("[*] Technical summary received."))
    except Exception as e:
        print(f"[!] Failed to generate OpenAI summary: {e}")

    print(fade.brazil(f"[*] Writing summary CSV to {summary_csv_path}"))
    headers = ["Technical Analysis Summary"]
    data_row = [technical_summary]
    ioc_keys_in_order = ["domains", "ips", "urls", "hashes", "emails", "filenames", "cves", "malware_families", "threat_actors", "mitre_ttps"]
    for key in ioc_keys_in_order:
        values = all_iocs.get(key)
        if values:
            headers.append(key.replace('_', ' ').title())
            if key in ["domains", "ips", "urls", "emails"]:
                data_string = ", ".join([defang(v) for v in sorted(list(values))])
            else:
                data_string = ", ".join(map(str, sorted(list(values))))
            data_row.append(data_string)

    with open(summary_csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        writer.writerow(data_row)

    print(fade.brazil("[*] Generating STIX 2.1 report at {stix_path}"))
    stix_objects = []
    author = Identity(name="haKC.ai - PANHANDLR ", identity_class="organization")
    stix_objects.append(author)
    
    now = datetime.now(timezone.utc)
    report = Report(
        name=f"Threat Intelligence Report - {now.isoformat()}",
        description=technical_summary,
        published=now,
        object_refs=[author.id],
        report_types=['threat-report']
    )
    
    indicator_refs = []
    for ip in all_iocs.get('ips', []):
        indicator = Indicator(pattern_type="stix", pattern=f"[ipv4-addr:value = '{ip}']", created=now, valid_from=now)
        indicator_refs.append(indicator)
    for domain in all_iocs.get('domains', []):
        indicator = Indicator(pattern_type="stix", pattern=f"[domain-name:value = '{domain}']", created=now, valid_from=now)
        indicator_refs.append(indicator)
    for h in all_iocs.get('hashes', []):
        h = h.lower()
        stix_hash_type = 'MD5' if len(h) == 32 else 'SHA-1' if len(h) == 40 else 'SHA-256' if len(h) == 64 else None
        if stix_hash_type:
            pattern = f"[file:hashes.'{stix_hash_type}' = '{h}']"
            indicator = Indicator(pattern_type="stix", pattern=pattern, created=now, valid_from=now)
            indicator_refs.append(indicator)
        else:
            print(f"[!] Skipping invalid or unsupported hash format for STIX: {h}")

    for actor_name in all_iocs.get('threat_actors', []):
        actor = ThreatActor(name=actor_name, created=now)
        indicator_refs.append(actor)
    for malware_name in all_iocs.get('malware_families', []):
        malware = Malware(name=malware_name, is_family=True, created=now)
        indicator_refs.append(malware)
        
    for cve_id in all_iocs.get('cves', []):
        vuln = Vulnerability(name=cve_id, external_references=[{"source_name": "cve", "external_id": cve_id}])
        indicator_refs.append(vuln)
    for ttp_id in all_iocs.get('mitre_ttps', []):
        mitre_url = f"https://attack.mitre.org/techniques/{ttp_id.replace('.', '/')}"
        ttp = AttackPattern(name=f"MITRE ATT&CK: {ttp_id}", external_references=[{"source_name": "mitre-attack", "external_id": ttp_id, "url": mitre_url}])
        indicator_refs.append(ttp)

    stix_objects.extend(indicator_refs)
    
    report.object_refs.extend([obj.id for obj in indicator_refs])
    stix_objects.append(report)

    bundle = Bundle(stix_objects, allow_custom=True)
    with open(stix_path, "w", encoding="utf-8") as f:
        f.write(bundle.serialize(pretty=True))


def process_links_from_csv(input_file, output_file):
    csv_headers = ["url", "title", "domains", "ips", "urls", "emails", "hashes", "filenames", "cves", "malware_families", "threat_actors", "mitre_ttps", "hunting_narrative"]
    all_iocs = {key: set() for key in csv_headers if key not in ["url", "title", "hunting_narrative"]}

    with open(output_file, "w", newline="", encoding="utf-8") as out_csv:
        writer = csv.writer(out_csv)
        writer.writerow(csv_headers)
        try:
            with open(input_file, "r", encoding='utf-8') as f_in:
                if os.fstat(f_in.fileno()).st_size == 0:
                    print(f"[!] Input file '{input_file}' is empty. Nothing to process.")
                    return {}
                reader = csv.DictReader(f_in)
                for row in reader:
                    link = row.get("dork_url")
                    title = row.get("title")
                    if not link:
                        print(f"[!] Skipping row with missing 'dork_url': {row}")
                        continue
                        
                    print(fade.greenblue(f"\n[+] Processing: {link}"))
                    iocs = {}
                    try:
                        if is_git_repo(link):
                            iocs = clone_and_extract_iocs_from_git(link)
                        else:
                            page_text = scrape_and_save_page(link, PROCESSING_DIR)
                            if page_text:
                                iocs = analyze_text_with_openai(page_text)
                                
                        if not iocs:
                            print(f"[!] No IOCs found or an error occurred for {link}. Skipping.")
                            continue
                            
                        row_data = [link, title]
                        for key in csv_headers[2:]:
                            values = iocs.get(key, [])
                            if isinstance(values, str): 
                                unique_values_str = values
                            else:
                                unique_values = sorted(list(dict.fromkeys(values))) 
                                if key in ["domains", "ips", "urls", "emails"]:
                                    defanged_values = [defang(v) for v in unique_values]
                                    unique_values_str = ", ".join(defanged_values)
                                else:
                                    unique_values_str = ", ".join(map(str, unique_values))
                                
                                if key in all_iocs:
                                    all_iocs[key].update(unique_values)
                            row_data.append(unique_values_str)
                            
                        writer.writerow(row_data)
                        out_csv.flush()
                        
                    except Exception as e:
                        print(f"[!] A critical error occurred while processing the link {link}: {e}")
                        
        except FileNotFoundError:
            print(f"[!] FATAL: Input CSV file not found at {input_file}")
            return {}
        except Exception as e:
            print(f"[!] FATAL: Could not process input CSV file '{input_file}'. Error: {e}")
            return {}
            
    return all_iocs

if __name__ == "__main__":
    base_dir = os.path.dirname(os.path.abspath(__file__))
    analysis_dir = os.path.join(base_dir, "..", "analysis")
    os.makedirs(analysis_dir, exist_ok=True)

    input_dorks_file = os.path.join(analysis_dir, "global_google_dorks_analysis.csv")
    
    if not os.path.exists(input_dorks_file):
        print(f"[!] Input file not found: {input_dorks_file}")
        print("[!] Please run the 'Dorking Phase' first to generate results.")
        exit()

    detailed_csv_output = os.path.join(analysis_dir, "detailed_ioc_report_defanged.csv")
    summary_csv_output = os.path.join(analysis_dir, "technical_summary_report_defanged.csv")
    stix_output_file = os.path.join(analysis_dir, "stix_threat_report.json")
    
    aggregated_iocs = process_links_from_csv(input_dorks_file, detailed_csv_output)
    
    if any(aggregated_iocs.values()):
        generate_summary_and_stix_report(aggregated_iocs, summary_csv_output, stix_output_file)
    else:
        print("\n[!] No IOCs were collected in the entire run. Skipping final report generation.")

    print(fade.purplepink(f"[+] Script finished."))
    print(fade.brazil(f"[+] Detailed (defanged) report saved to: {detailed_csv_output}"))
    print(fade.brazil(f"[+] Technical Summary (defanged) report saved to: {summary_csv_output}"))
    print(fade.brazil(f"[+] Machine-Readable STIX 2.1 report saved to: {stix_output_file}"))