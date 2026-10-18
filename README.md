# Phishing Link Checker

A rule-based Python tool that analyses a URL and returns a risk verdict (**Safe**, **Suspicious** or **Dangerous**) along with the specific reasons behind it.

Built for the *Problem Solving in Python* course.

---

## Features

- Checks a single URL or a list of URLs
- Scores each URL using eight independent rules
- Explains every flag, so the result is never a black box
- Uses only Python's standard library, so there is nothing to install

---

## How It Works

1. **Normalise** the input. A bare domain such as `paypa1.com` gets `http://` added so it can be parsed.
2. **Parse** the URL once with `urllib.parse.urlparse`.
3. **Run the rules.** Each rule takes the parsed URL and returns `(points, reason)`.
4. **Add up the points** and map the total to a verdict.

| Verdict | Score |
|---|---|
| Safe | 0 |
| Suspicious | 1 to 19 |
| Dangerous | 20 or more |

### Rules

| Rule | Points | What it looks for |
|---|---|---|
| No HTTPS | 10 | Connection is not encrypted |
| Lookalike domain | 5 | Brand names with digits swapped for letters (e.g. `paypa1`, `g00gle`) |
| IP address | 15 | Domain is a raw IP such as `192.168.0.1` |
| Suspicious keyword | 8 | Words such as `verify`, `login`, `update`, `free` |
| Shortened link | 12 | Known shorteners such as `bit.ly` or `tinyurl.com` |
| Long URL | 6 | More than 75 characters |
| Too many subdomains | 10 | More than three dots in the domain |
| Special characters | 8 to 15 | `@` in the URL, or too many hyphens in the domain |

---

## Project Structure

```
Phishing-Detector/
├── Python_Project.py   # Rules, scoring and the command-line interface
├── README.md           # This file
└── .gitignore
```

---

## Getting Started

**Requirements:** Python 3.8 or newer. No external packages are needed.

```bash
git clone https://github.com/<your-username>/<your-repo-name>.git
cd <your-repo-name>
python Python_Project.py
```

**Example session**

```
Enter the URL: http://paypa1.com/verify

Verdict: Suspicious (score: 13)
  - No HTTPS.
  - Lookalike of 'paypal' detected.
  - Suspicious keyword in path: 'verify'.
```

---

## Testing

The rules were checked against a labelled set of safe and suspicious URLs.

| Input | Expected |
|---|---|
| `https://www.google.com` | Safe |
| `https://web1.com` | Safe |
| `paypa1.com/verify` | Suspicious |
| `http://192.168.0.1/login` | Dangerous |
| `https://free-gifts.bit.ly` | Dangerous |

> Add your own test cases to this table before submission.

---

## Limitations

- Rules are **heuristic**. A high score means "worth checking", not "definitely a scam", and legitimate links can be flagged.
- The brand list is short and only covers well-known names.
- The checker never visits the URL, so it cannot see page content or redirects.
- Keyword matching is simple substring matching and can produce false positives.

