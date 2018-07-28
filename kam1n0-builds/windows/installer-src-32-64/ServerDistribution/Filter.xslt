<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0"
xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
xmlns:wix="http://schemas.microsoft.com/wix/2006/wi">
  <xsl:output method="xml" indent="yes" />
  <xsl:template match="@*|node()">
    <xsl:copy>
      <xsl:apply-templates select="@*|node()"/>
    </xsl:copy>
  </xsl:template>
  <xsl:key name="service-search" match="wix:Component[wix:File/@Source = '$(env.KAM_DIST)\Kam1n0.exe']" use="@Id" />
  <xsl:template match="wix:Component[key('service-search', @Id)]" />
  <xsl:template match="wix:ComponentRef[key('service-search', @Id)]" />
</xsl:stylesheet>