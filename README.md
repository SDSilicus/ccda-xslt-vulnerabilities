## Security vulnerabilities in C-CDA display: a case study

## For background

See my [smartplatforms.org blog
post](http://smartplatforms.org/2014/04/security-vulnerabilities-in-ccda-display/)
describing the details of three security vulnerabilities in C-CDA Display using
CDA.xsl in HL7's CDA.xsl.

## The story


Last month I discovered a set of security vulnerabilities in a **well-known
commericial EHR product** that I'll pseudonomously call "Friendly Web EHR".
Here's the story...

### Discovery

I was poking around my account in Friendly Web EHR, examining MU2 features like
C-CDA display and Direct messaging. I use the "file upload" feature to upload
some sample documents from SMART's [Sample C-CDA Repository on
GitHub](https://github.com/chb/sample_ccdas) to see how well they rendered. At
the time, I was thinking about the user experience. (Specifically, I was
bemoaning how clunky the standard XSLT-based C-CDA rendering looks.) I was
curious to see how the C-CDA viewer was embedded into the EHR. Direct DOM
insertion? Inline frames? I opened up Chrome Developer Tools to take a look.

It turned out to be an `iframe` pointing to a standalone C-CDA viewer module.
Interestingly the `src` URL of the iframe included two URL parameters: an
identifier for the document that I was viewing, and some kind of security
token. A bit of investigation revealed that this token was identical to my main
EHR session token: in other words, a full session-equivalent was embedded into
the `iframe/@src` URL.

This was dangerous, because it meant that a malicious document could steal my
EHR session merely by leaking its own URL to an attacker. This kind of leakage
occurs by default in modern web browsers, in the form of `Referer` headers:
every time a typical browser fetchese external resources like an image, it
includes a header with the URL of the current page.  So if I could merely
reference an external image in my C-CDA, I'd have an attack vector.

I started looking through HL7's [example
stylesheet](https://github.com/chb/sample_ccdas/blob/b052e21f8f314b49753d8f74967ac40ea5c30948/CDA.xsl)
and saw that the
[`renderMultiMedia`](https://github.com/chb/sample_ccdas/blob/b052e21f8f314b49753d8f74967ac40ea5c30948/CDA.xsl#L1285)
template allowed the creation of `img` tags with an arbitrary `src` attribute.
That would be all I needed...

But it occurred to me that a 2274-line XSLT file written in 2008 probably had
other vulnerabilities. I started hunting for loopholes that would allow
execution of javascript code, and I discovered the [two vulnerabilities I
described in my SMART Platforms blog
post](http://smartplatforms.org/2014/04/security-vulnerabilities-in-ccda-display/).

I decided to try these out against my own account in Friendly Web EHR, and sure enough I was able to:

1. Leak a session token back to a remote server, and
2. Execute arbitrary JavaScript in the browser, accessing cookies as well as a
   session token


> If you're interested in exploring a low-fidelity re-creation of the
> vulnerable C-CDA viewer, I've put together a working [simulation that
> demonstrates the key
> issues](http://chb.github.io/ccda-xslt-vulnerabilities/). Don't worry: it's
> just a demonstration, and perfectly safe to view!
> [*simulation*](https://chb.github.io/ccda-xslt-vulnerabilities) | 
> [*source*](https://github.com/chb/ccda-xslt-vulnerabilities)

At this point, about 5pm on a Saturday, I reported the discovery by e-mail to a
contact at Friendly Web EHR. I heard back Sunday evening with a request for
more details. I provided these, including an example document demonstrating the
vulnerabilities (see the simulation above). They confirmed the vulnerabilities,
and over a few follow-up sessions we discussed the problems in detail. By that
Thursday night (five days after the report) they had a fix in place.

### Round two: non-XSLT viewers and viral vectors

When I returned to Friendly Web EHR after the initial fix was ready, I realized
that the EHR actually included two different C-CDA viewers. The one I had
initially explored was based on HL7's CDA.xsl, but a second viewer offered a
much more compelling user experience. This second viewer was built directly
into the EHR's Direct inbox feature, and could be used to open C-CDA
attachments to Direct messages.

When I looked through the JavaScript source code, I noticed Friendly Web EHR
used the [Handlebars](http://handlebarsjs.com/) templating library to insert a
C-CDA view into the Direct inbox -- and that view was inserted using an
unscaped markup expression (handlebars syntax: `{{{ unescaped_markup_here
}}}`). This was potentially an opportunity to inject rogue markup into the DOM.

I set up a [HealthVault](https://www.healthvault.com) account and discovered
that as a patient, I could send Direct messages to my clinician account in
Friendly Web EHR. Using this account, I tried sending documents with the
exploits that I had discovered in my CDA.xsl explorations, but to no avail.

And then on a hunch I tried adding a `CDATA` block to a C-CDA narrative text
element, to create something like:

```
<section>
  <text>
    <![CDATA[
       <script>
          alert('document.cookie');
       </script>
    ]]>
  </text>
</section>
```

This resulted in HTML that was *close* to what I needed, but the opening
`script` tag was wrapped in a comment block. Something like:

```
 <!-- <script> -->
 alert('document.cookie');
 </script>
```

Again on a hunch, I tweaked my payload by duplicating the opening `<script>`
tag -- and sure enough, I was able to inject JavaScript into the EHR session!

## Serious danger: potential for viral spread

This vulnerability was potentially far more concerning than the earlier ones,
because it was an issue with the C-CDA viewer attached to Friendly Web EHR's
Direct inbox.  What this means is that a motivated attacker could turn this
vulnerability into a viral (self-spreading) vector, by following a sequence of
steps like:

1. Craft a malicious document and send it via Direct message to any Friendly
   Web EHR clinician.

2. When viewed, the document hijacks a user's EHR session and issues a set of
   calls to Friendly Web EHR's internal (undocumented) API.

3. API call to fetch a clinician's contacts from her address book.

4. API call to send a new Direct message to each contact, containing a new copy
   of the malicious document.  (To make this realisitic, it would be designed
   to look like a referral note with patient data attached.)

This sequence of steps could allow an attacker to harvest large quantities of
protected health information in short order.

## Wrapping up

I reported this additional vulnerability to Friendly Web EHR, and they fixed it
by the following Thursday.

In the meantime, I attempted to contact every Web-based EHR vendor I could
identify, to notify them about the CDA.xsl vulnerabilities. I'll describe the
discouraging results of that reporting effort in a subsequent post!
