# Create your own processor definition

To add a customized processor architecture is simple. Follow these steps:

* Create an xml file according to the template in this page.
* Put it under your %kam1n0_installation_directory%/architectures/
* Open the workbench, Now you can create a repository with your own processor architecture.

## XML scheme for defining the processor specific assembly language

The definition of your own processor specific assembly language should follow the scheme below. You can find example definitions for arm, powerpc, and metapc under the directory `%kam1n0_installation_directory%/architectures/`. It should be noted that the xml definition of the assembly language does not need to be strictly inclusive. Missing some rarely used suffix for the operations will not have significant impact on the clone search result.

```xml

<?xml version="1.0" encoding="UTF-8"?>
   <xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema" elementFormDefault="qualified" attributeFormDefault="unqualified">
         <xs:element name="Kam1n0-Architecture">
               <xs:complexType>
                     <xs:sequence>
                           <xs:element name="processor" type="xs:string"></xs:element>
                           <xs:element name="operations">
                                 <xs:complexType>
                                       <xs:sequence>
                                             <xs:element name="operation" maxOccurs="unbounded">
                                                   <xs:complexType>
                                                         <xs:sequence>
                                                               <xs:element name="suffixGroup" type="xs:string"></xs:element>
                                                         </xs:sequence>
                                                         <xs:attribute name="identifier" type="xs:string"></xs:attribute>
                                                   </xs:complexType>
                                             </xs:element>
                                       </xs:sequence>
                                 </xs:complexType>
                           </xs:element>
                           <xs:element name="operationJmps">
                                 <xs:complexType>
                                       <xs:sequence>
                                             <xs:element name="operation" maxOccurs="unbounded">
                                                   <xs:complexType>
                                                         <xs:sequence>
                                                               <xs:element name="suffixGroup" maxOccurs="unbounded" type="xs:string"></xs:element>
                                                         </xs:sequence>
                                                         <xs:attribute name="identifier" type="xs:string"></xs:attribute>
                                                   </xs:complexType>
                                             </xs:element>
                                       </xs:sequence>
                                 </xs:complexType>
                           </xs:element>
                           <xs:element name="suffixGroups">
                                 <xs:complexType>
                                       <xs:sequence>
                                             <xs:element name="suffixGroup" maxOccurs="unbounded">
                                                   <xs:complexType>
                                                         <xs:sequence>
                                                               <xs:element name="suffix" maxOccurs="unbounded"></xs:element>
                                                         </xs:sequence>
                                                         <xs:attribute name="identifier" type="xs:string"></xs:attribute>
                                                   </xs:complexType>
                                             </xs:element>
                                       </xs:sequence>
                                 </xs:complexType>
                           </xs:element>
                           <xs:element name="registers">
                                 <xs:complexType>
                                       <xs:sequence>
                                             <xs:element name="register" maxOccurs="unbounded">
                                                   <xs:complexType>
                                                         <xs:attribute name="identifier" type="xs:string"></xs:attribute>
                                                         <xs:attribute name="category" type="xs:string"></xs:attribute>
                                                         <xs:attribute name="length" type="xs:int"></xs:attribute>
                                                   </xs:complexType>
                                             </xs:element>
                                       </xs:sequence>
                                 </xs:complexType>
                           </xs:element>
                           <xs:element name="lengthKeywords">
                                 <xs:complexType>
                                       <xs:sequence>
                                             <xs:element name="lengthKeyWord">
                                                   <xs:complexType>
                                                         <xs:attribute name="identifier" type="xs:string"></xs:attribute>
                                                         <xs:attribute name="length" type="xs:int"></xs:attribute>
                                                   </xs:complexType>
                                             </xs:element>
                                       </xs:sequence>
                                 </xs:complexType>
                           </xs:element>
                           <xs:element name="jmpKeywords"></xs:element>
                           <xs:element name="lineFormats">
                                 <xs:complexType>
                                       <xs:sequence>
                                             <xs:element name="syntax" maxOccurs="unbounded">
                                                   <xs:complexType>
                                                         <xs:sequence>
                                                               <xs:element name="lineRegex" type="xs:string"></xs:element>
                                                         </xs:sequence>
                                                         <xs:attribute name="numberOfOperand" type="xs:int"></xs:attribute>
                                                   </xs:complexType>
                                             </xs:element>
                                       </xs:sequence>
                                 </xs:complexType>
                           </xs:element>
                           <xs:element name="constantVariableRegex" type="xs:string"></xs:element>
                           <xs:element name="memoryVariableRegex" type="xs:string"></xs:element>
                     </xs:sequence>
               </xs:complexType>
         </xs:element>
   </xs:schema>
```





