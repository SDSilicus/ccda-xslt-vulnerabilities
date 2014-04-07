# Disturbing state of EHR Security Vulnerability Reporting

Last week I [reported on a set of security vulnerabilities](http://smartplatforms.org/2014/04/security-vulnerabilities-in-ccda-display/) that affected multiple EHR vendors and other Health IT systems.

I initially discovered the vulnerability in a single Web-based EHR system
and [successfully reported it directly to that vendor](http://smartplatforms.org/2014/04/case-study-security-vulnerabilities-in-ccda).

*But my subsequent journey into the world of EHR vulnerability reporting left
me deeply concerned that our EHR vendors do not have mature reporting systems
in place. Patient health data are among the most personal, sensitive aspects of
our online presence. They offer an increasingly high-value target for identity
theft, blackmail, and ransom. It's time for EHR vendors to take a page from the
playbook of consumer tech companies by instituting the same kinds of security
vulnerability reporting programs that are ubiquitous on the consumer Web.*

## HL7 and EHR Vendors must address security reporting

I'll lead with the key message here, and provide supporting evidence below:
HL7 and EHR vendors need to institute security vulnerability reporting programs!

In any complex system, bugs -- including security vulnerabilities -- are a fact
of life.  But an important part of being prepared is having a well-defined
channel for security researchers, concerned citizens, and others to reach out
and report what they find. This could take the form of:

 * Bug Bounty or "Whitehat" program like [Github's](https://bounty.github.com/) or [Facebook's](https://www.facebook.com/whitehat)
 * Well-defined vulnerability reporting page like [Twitter's](https://support.twitter.com/forms/security)

These programs sometimes award fame, or cash -- but they key point is that they
provide a **single "right way" to report** issues, and the best programs **publicize all finding as a matter of course**, so the community can grow and learn.

Here's a [whole list of programs](https://bugcrowd.com/list-of-bug-bounty-programs/) that could be used as models.

What follows is a summary of my experience attempting to engage with HL7 and EHR vendors in a responsible disclosure process.


## No official reporting channels

The vulnerability I discovered was unusual in that it stemmed from source code
provided by HL7, the international health standards organization. This code was
directly incorporated into an unknown number of health IT products, and many of
those products could be vulnerable. I first contacted John Moehrke, a security
co-chair for HL7, but he and his colleagues advised me that "that there really
is no private channel way to communicate with vendors in HL7".

It was not clear how best to proceed. I wanted to notify the public, but before
that I wanted to warn the developers of affected systems. The problem was that
I didn't know who those developers were, and the overall potential pool was
vast.  With advice from friends and colleagues, I decided to reach out directly
to the set of Web-based EHR vendors in the US, because those were the systems I
thought were most likely to be affected. In retrospect, a still-wider circle
including international vendors and non-vendor health IT systems may have been
better -- but sharing a "private" warning with too large a group becomes impractical. *Because patient data were at stake and I couldn't tell for sure which systems might be affected, I believed that responsible disclosure argued for getting the word out in a timely fashion.*

As a practical matter, I downloaded [Melissa McCormack's list of Web-based
EHRs](http://www.softwareadvice.com/medical/web-based-emr-software-comparison/),
which at the time included 82 products for which I could identify an active Web
presence. I attempted to [notify each vendor](https://github.com/chb/ccda-xslt-vulnerabilities/blob/master/to-vendors.md) via three channels:

1. Using any vendor-identified security vulnerability reporting mechanism (`*`)

2. By email to `security@{vendor-domain}` (per [OSASP
guidelines](https://www.owasp.org/index.php?title=Manage_security_issue_disclosure_process&setlang=es))

2. By email to any other vendor-supplied address (`info@`, `sales@`, etc) or
private contacts if available.

`*`: In reviewing 83 vendor Web sites, **I was not able to identify an
official security vulnerability reporting mechanism in any case.**  (In
retrospect, I may have missed some channels that did not turn up via Google search or within the searchable text of any Web page, such as the "What can we help you with" drop-down options in [GE Healthcare's contact page](http://www3.gehealthcare.com/en/About_Us/Contact_Us).)

**Furthermore, 55 out of 83 emails to `security@` were returned as
undeliverable.**

In ten cases where I was not able to reach a vendor by any of the three
channels above, I sent a notification directly through a Web-based contact for
on the vendor web site. This worked in all but one case, where  I received the
following message:

> "We are sorry, but the system thinks your message contains unwanted
> advertising, so it was blocked. If you think it's an error, please go back
> and retry avoiding words wuch as www, http, and so on."

## < 10% response rate

My notification included a request for responses so I could track
dissemination, but I received only seven responses:

* **Two vendors** requested a week to review
* **Two vendors** informed me that their systems were not vulnerable
* **One vendor** informed me that their product was vulnerable (and a fix was in progress)
* **One vendor** informed me that their product was a white-labeled version of another vendor's product
* **One vendor** simply confirmed receipt

This was a response rate of less than ten percent for a targeted and
potentially high-impact vulnerability report.
