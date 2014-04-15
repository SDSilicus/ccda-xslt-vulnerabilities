## How to protect yourself: a defense-in-depth approach

There are many, many ways to defend against an attack like this. In one sense,
it's not at all hard. But mistakes can be subtle, so it's extremely valuable to
protect yourself in a systematic way. By thinking
systematically, you can help prevent not only the attacks that you're
imaginitive enough to foresee, but others, too.

We'll discuss strategies to:

1. Keep bad documents out
2. If bad documents get in, prevent them from running code in the browser
3. If bad documents run code in the browser, ensure they can't steal critical application state like security tokens
4. If bad documents steal security tokens, limit the damage

### Keep bad documents out

The simplest practice here is to validate all incoming C-CDA documents against
the official CDA schema from HL7. Unfortunately the schema aren't easily
accessible on the Web (like so much of HL7's output), so the best I can do is
[link to the
zip](https://www.hl7.org/documentcenter/private/standards/cda/CDAR2_IG_IHE_CONSOL_DSTU_R1dot1_2012JUL.zip)
that contains the schema. This validation would reject documents containing
invalid attributes like `onmouseover` or `style`:

```
$ xmllint --schema CDA.xsd  potentially-valid-ccda.xml

Schemas validity error: 
  Element '{urn:hl7-org:v3}table', attribute 'onmousover':
    The attribute 'onmousover' is not allowed.
```

That's certainly a good start -- and if Friendly Web EHR had done something
like this before passing a C-CDA document into an XSL transform process, they
wouldn't have been vulnerable to the "rogue attributes" attack described above.

But validation alone won't ensure safety... you also need to


### Prevent documents from running code or loading external images

The next line of defense is to ensure that bad documents can't do bad things,
even if they do make it into our system. There are two key recommendations here:

1. Fix up the XSLT. Specifically: augment it to prevent blindly copying "all attributes" when
   rendering tables, and consider blocking external images as well).

2. Load the rendered C-CDA inside `<iframe SANDBOX="">` to prevent any
   JavaScript from running. This won't work on all browsers, but it provides an
extra measure of protection [where it does
work](http://caniuse.com/#feat=iframe-sandbox).

### Prevent documents from stealing critical application state even if they can run code or load images

Let's assume all our defenses up to this point have failed. With the right
protections in place, we can stay safe. At this level, we want to ensure that
C-CDAs are rendered and displayed in a "protected" environment, which means:

 * **No secret state embedded in the URL**. For example, it's a bad practice to
   use `iframe` source URLs with embedded tokens like
`/patient/john-smith/ccda/rendered?secret_token=123abc`. If you need to pass
credential to your C-CDA viewer, do it via `POST` instead of `GET`, or hide the
logic behind a token-stripping `redirect`. 

 * **No secret state in JavaScript-accessible cookies**. If you're using cookies
   for authentication, ensure that they're inaccessible to JavaScript (that is:
use the `httpOnly` flag, and `secure` for good measure).

 * **No shared origin with the parent frame**. If your `iframe` share its
   origin with the parent frame, then any code running within the `iframe` has
full access to the application state of the parent frame. This is dangerous! (
(See the effect of a compromise in  [the demo](https://chb.github.io/chb/ccda-xslt-vulnerabilities).) 
It's safer to load the C-CDA viewer in its own origin, where it simply can't
"see" the surrounding application. Better still, ensure that the C-CDA viewer
does not share a subdomain with the parent window, to ensure there is not even
an opportunity for shared cookies. 

### Limit the damage of exposed tokens

If all else fails, we can endeavor to limit the damage from leaked tokens. At this
point we're already dealing with a breach of protected health information, but
a small breach is much, much better than a massive one.  In this category we
have approaches like:

 * Bind sessions to end-user IP addresses, or at least geographical regions. If
   an attacker does steal a session token, we can still prevent the wholesale
   exposure of patient data directly to a remote sever.  Keep in mind that
this isn't an ircon-clad fix. An attacker can always hijack the end-user's
browser to execute and proxy arbitrary HTTP requests. For a vivid depiction of
how bad things can get, and how fast, see Krzysztof Kotowicz's [detailed blog
post](http://blog.kotowicz.net/2013/12/rapportive-xsses-gmail-or-have-yourself.html) (and especially the video!)
describing the exploitation of a vulnerability in the
[Rapportive](https://rapportive.com/) Chrome extension.

 * Monitor access patterns in realtime, and respond to anomolous behavior. Too
   many requests using a given access token, over too short a period of time,
for example, should trigger session expiration and user account locking.


## Bugs happen. Be prepared!

In any complex system, bugs -- including security vulnerabilities -- are a fact of life.
But an important part of being prepared is having a well-defined channel for 
security researchers, concerned citizens, and others to reach out
and report what they find. This could take the form of:

 * Bug Bounty or "Whitehat" program like [Facebook's](https://www.facebook.com/whitehat)
 * Well-defined vulnerability reporting page like [Twitter's](https://support.twitter.com/forms/security)

These programs sometimes award fame, or cash -- but they key point is that they provide 
a single "right way" to report issues.  Here's a [whole list of programs](https://bugcrowd.com/list-of-bug-bounty-programs/) that
you can explore. Please use them to model your own!
