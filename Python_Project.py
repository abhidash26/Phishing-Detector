from urllib.parse import urlparse
#The function uses urlparse and .scheme which shows the protocol used (http/https).
def check_https(parsed):
    if parsed.scheme != 'https':
        #10 points along with the reason why points are given.
        return(10, "No HTTPS.") 
    return(0,"")

#the function uses urlparse's .hostname to check for a simple lookalike.
def check_lookalike(parsed):
    domain=parsed.hostname
    #checking basic lookalikes.
    if '0' in domain or '1' in domain:
        return (5,"lookalike character detected.")
    return(0,"")

#The next function checks whether a url used an IP address instead of a domain.
def check_ip(parsed):
    if all(part.isdigit() for part in parsed.hostname.split('.')):
        return(15,"Uses an IP address instead of a domain.")
    return(0,"")

#The function checks for suspicious keywords by using like verify, login, update,etc. using .geturl()
def check_sus_keywords(parsed):
    #First we define a list of common keywords.
    keywords=['verify','login','update','free','confirm','urgent','click']
    full_url=parsed.geturl().lower()# used lowercase so that we need not worry about random capitalisation.
    for keyword in keywords:
        if keyword in full_url:
            return(8,f'Suspicious keyword: {keyword}')
    return(0,"")

#The function checks for shortened URLs such as tinyurl or bit.ly
def check_shortened(parsed):
    #A lsit of common shortened URLs.
    short=['bit.ly','tinyurl','goo.gl','short.link','ow.ly']
    domain=parsed.hostname.lower()
    for word in short:
        if word in domain:
            return(12, f"Detected a shortened link: {word}")
    return(0,"")

#The function checks if a url is unusually long 
def check_length(parsed):
    full_url=parsed.geturl()
    #average url length lies between 40 and 80 characters. So, selected the limit as 75.
    if len(full_url)>75:
        return(6, "URL is unusually long.")
    return(0,"")

#The function checks whether a url has too many subdomains. This is a common phishing tactic. More than n dots:n+1 subdomains.
def check_subdomain(parsed):
    domain=parsed.hostname.lower()
    subdomain_count=domain.count('.')
    if subdomain_count>3:
        return(10,"Too many subdomains")
    return(0,"")

#The function checks whether a URL has '@' or too many hyphens. This is a common spoofing tactic.
def check_special(parsed):
    fullurl=parsed.geturl()
    if '@' in fullurl:
        return(15,"Contains '@'. A common spoofing tactic.")
    domain = parsed.hostname.lower()
    if domain.count('-') > 2:
        return (8, "Too many hyphens in domain")
       
    return(0,"")

#Normalize the URL before passing it fro scoring
def normalize(url):
    url=url.strip()
    if '://' not in url:
        url='http://'+url
    return urlparse(url)

#The main scroing function. It parses the URL once, runs all checks, and returns the verdict.
#It returns: the score, the verdict, and the list of reasons.
def score_url(url):
    try:
        parsed=normalize(url)
    except:
        return(0,"Invalid URL.",["Could not parse URL."])
    if not parsed.hostname:
        return (0, "Invalid URL.", ["No domain found in URL."])
    total_score=0
    reasons=[]
    #Now we call all the rule functions and store the outputs in a list.
    checks=[
        check_https(parsed),
        check_lookalike(parsed),
        check_ip(parsed),
        check_sus_keywords(parsed),
        check_shortened(parsed),
        check_length(parsed),
        check_subdomain(parsed),
        check_special(parsed)
    ]
    #Now we parse through the list for points and reasons.
    for points,reason in checks:
        total_score+=points
        if reason:
            reasons.append(reason)
    #Determine the final verdict based on the score.
    if total_score==0:
        #Safe as per rules.
        verdict='Safe'
    elif total_score<20:
        #A few worrying signals butnothing that is extremely fishy.
        verdict='Suspicious'
    else:
        #A combination of many worrying signals.
        verdict='Dangerous'
    return(total_score, verdict, reasons)

url=input("Enter the URL: ").strip()
print(url)
score,verdict,reasons=score_url(url)
print(f"\nURL: {url}")
print(f"Score: {score}")
print(f"Verdict: {verdict}")
if reasons:
    print("Reasons:")
    for r in reasons:
        print(f"  - {r}")