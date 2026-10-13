# Bluebeam Revu 21 Data Formats and Markups Technical Specification

This technical specification provides primary-source documented details regarding Bluebeam Revu 21 data formats, configuration structures, markup definitions, stamp dictionaries, and administration interfaces discovered on `the reference workstation`.

---

## 1. File Locations (Windows, Revu 21)

Primary configuration files, toolsets, profiles, stamps, and plugins are located across standard Windows directories:

* **Program Data (Global / Shared)**: `C:\ProgramData\Bluebeam Software\Bluebeam Revu\21\`
  * Subdirectories:
    * `Stamps/`: Contains built-in and localized Stamp PDFs (e.g., `Approved.pdf`, `Date.pdf`, `DateTime.pdf`, `DraftPrint.pdf`, `ForReview.pdf`, `Seal.pdf`, `Watermark.pdf`, and language subfolders `da`, `de`, `en-GB`, `es`, `fi`, `fr`, `it`, `ja`, `ko`, `nl`, `no`, `sv`).
    * `Pushbutton PDF/`: Page setup plugins (`AutoCAD.plugin.xml`, `SolidWorks.plugin.xml`, `Samples/FileProperties/Sample.xml`).
    * `Revu/`: Global feature flags (`FeatureFlags.xml`, `FontCache.xml`).
* **Roaming User Profile (Per-User Settings & Toolsets)**: `%APPDATA%\Bluebeam Software\Revu\21\`
  * Subdirectories & Files:
    * **Tool Sets (.btx)**: `Architect Review.btx`, `Concrete.btx`, `Construction Symbols.btx`, `Contractor Review.btx`, `Design Symbols.btx`, `Electrical.btx`, `Engineer Review.btx`, `Fire, Life Safety & Security.btx`, `General Use.btx`, `Interior Finishes.btx`, `Mechanical.btx`, `My Tools.btx`.
    * **Profiles (.bpx)**: `Essentials.bpx`, `Field Issues.bpx`, `Quantity Takeoff.bpx`, `Revu Advanced.bpx`, `Revu.bpx`, `_BuiltIn\FullScreen.bpx`.
    * **Preferences & XML Config**: `ApplicationSettings.xml`, `Construction.xml`, `KeyboardShortcuts.xml`, `UserPreferences.xml`.
    * **User Subdirectories**: `RevuUsers\<user-guid>\Revu.xml`, `Categories\Construction.xml`.
* **Program Files (Application Binaries & Administrator)**: `C:\Program Files\Bluebeam Software\Bluebeam Revu\21\`
  * Subdirectories & Files:
    * `Revu/PbMngr5.exe`: Bluebeam Administrator command-line management executable.
    * `Revu/Revu.exe`: Main application binary.
    * Visual Elements Manifests: `Pushbutton PDF\Bluebeam Plugins Administrator.VisualElementsManifest.xml`, `Revu\Bluebeam Script Editor.VisualElementsManifest.xml`, `Revu\Revu.VisualElementsManifest.xml`, `Revu\Stapler.VisualElementsManifest.xml`.

---

## 2. Exact XML Schema of Tool Set Files (`.btx`)

Tool set files (`.btx`) define custom tool chests containing markup templates. As observed in local files such as `Architect Review.btx`, the root element is `<BluebeamRevuToolSet Version="1">`.

### Structure & Verbatim Examples
1. **Title**: Encodes either plain text or a zlib-compressed hex stream (e.g., `789c732c4acec82c494d2e51084a2dcb4c2d0700338e062a`).
2. **ToolChestItem**: Represents individual tools in the chest. Attributes include `Version="1"` or `Version="2"`.
   * `<Name>`: Identifier string or compressed name (e.g., `QRGOYETREOFCJYJO`).
   * `<Type>`: Fully qualified .NET type indicating the markup class (e.g., `Bluebeam.PDF.Annotations.AnnotationPolygon`, `Bluebeam.PDF.Annotations.AnnotationFreeText`, `Bluebeam.PDF.Annotations.AnnotationInk`, `Bluebeam.PDF.Annotations.AnnotationLine`, `Bluebeam.PDF.Annotations.AnnotationMeasurePolylength`, `Bluebeam.PDF.Annotations.AnnotationMeasureArea`).
   * `<Raw>`: Zlib-compressed byte stream (hex-encoded) containing property dictionaries, coordinate arrays, and style parameters. For instance, in `Architect Review.btx`:
     ```xml
     <ToolChestItem Version="2">
       <Name>QRGOYETREOFCJYJO</Name>
       <Type>Bluebeam.PDF.Annotations.AnnotationPolygon</Type>
       <Raw>789c6d505d6f823014fd2b7ddc5eb82d22658921a1e0145446a06e66c407878d76a942b024f2ef57c83e5e76efcb3de7dcefd90c620e59adfa537d0d55dd1d0d9edf47868bbb8657d16a59895b49a616711d8f228a2dcf71a6e897f80b8608dbde3fcc77d11e9ea5522fcda192ba47d872806d60d3292d1bd543d17d7c3e046d75965a54fa11b8b8343987455b77cd086283d224784fc26d9215bb5590acd6a330a6a4e2a6e5f5941e2e0216d136676b9e2c73ce7651940dbd75df889f532137134a8c3022136cd92ea5c8732d8c9f26d4ec881c084b6244bc0756981fbd210285713eb460757b14adef039b1ba980106264fbc6be007c0360a5</Raw>
       <X>15.1649</X>
       <Y>-24.71643</Y>
       <Index>0</Index>
       <Child>
         <Type>Bluebeam.PDF.Annotations.AnnotationFreeText</Type>
         <Raw>789c75915f6b833014c5bf4a602fca68621a157565e09fd9d696aea86565e283b3a9cd48555c3ada6fbfc4873128bb97bc9c93df4d0e77364391af6160c81e1a8016947f033c05f95147cb1cc503a539bd8ab0e2bcbb0829bd5cd1b6e33725a228d38e5d2b3ca0282a585d49b4174f4048775271d6b41ea747299caba161ad4794c9594b2727ca9a93f030818ed2ea8e7783f710c7862c1da551614da1693896092c688d07bbd0b131714b14ae0b251017da36c6049029b40dc77401b620715d473223fc4729514ecf7d1074d74225c50e81ae9c0e4c0b6235a34431e3fcb5af6a266ec08026ca2e1f9f5a28431f1ef511de5467ba8cd026f1df9370976cb3fdca4f56ebd19b0fdda5dfd02fc1daa6d0fca13e31416ba1dfdf9e47bb3458e7c922cd837d146dcb3b5ebd73cfc9ef885b4f7f17825239ffdf2cc0446151a22093eb7d0306ca64e70a0fbae1408767593f3a3b9473</Raw>
         <X>-100.8294</X>
         <Y>5.5</Y>
         <Index>1</Index>
       </Child>
       <Mode>properties</Mode>
     </ToolChestItem>
     ```
   * `<Resources>`: Container block used in measurement toolsets (e.g., `Concrete.btx` and `Construction Symbols.btx`) storing calibration and scaling definitions via nested `<ID>` and `<Data>` zlib streams.

---

## 3. Exact XML Schema of Profile Files (`.bpx`)

Profile files (`.bpx`) store layout configurations, toolbar states, panel arrangements, and markup list column definitions. As seen in `Essentials.bpx`, `Field Issues.bpx`, and `Quantity Takeoff.bpx`, the root element is `<RevuProfile Version="1" Name="...">`.

### Structure & Verbatim Examples
* **Record Key="MarkupList"**: Configures columns, widths, visibility, and ordering in the Markups List panel.
  ```xml
  <Record Key="MarkupList">
    <ActiveColumn>0</ActiveColumn>
    <Columns>
      <Column Key="Subject">
        <Width>198</Width>
        <Visible>True</Visible>
        <Added>True</Added>
      </Column>
      <Column Key="Page">
        <Width>100</Width>
        <Visible>True</Visible>
        <Added>True</Added>
      </Column>
      <Column Key="Status">
        <Width>108</Width>
        <Visible>True</Visible>
        <Added>True</Added>
      </Column>
      <Column Key="UserDefined0">
        <Width>136</Width>
        <Visible>True</Visible>
        <Added>True</Added>
      </Column>
    </Columns>
  </Record>
  ```

---

## 4. Exact PDF Dictionary Structure of Bluebeam Stamps and Markups

Bluebeam Stamps (stored as PDF files in `C:\ProgramData\Bluebeam Software\Bluebeam Revu\21\Stamps\`) are standard PDF documents containing specialized interactive annotations (`/Annot`) on Page 0. Based on `pypdf` inspection dumps in `r3_formats_dump.txt`:

### Metadata Dictionary (`/Info` or Catalog)
```python
{
  '/CreationDate': "D:20120314093118-07'00'",
  '/ModDate': "D:20120316163227-07'00'",
  '/Author': '',
  '/Creator': 'Bluebeam Revu x64',
  '/Producer': 'Bluebeam PDF Library 10.0.0',
  '/Title': 'Approved',
  '/BlendMode': 'Normal',
  '/Opacity': '1',
  '/Rotation': '0',
  '/ID': '#YNWFUEUNHUGOSYFZ'
}
```

### Page Annotation Dictionary (`/Annots`)
For `Approved.pdf`, the page annotation dictionary exposes:
```python
{
  '/Subj': 'Text Box',
  '/Type': '/Annot',
  '/P': IndirectObject(5, 0),
  '/F': 4,
  '/C': [],
  '/CreationDate': "D:20120314093122-07'00'",
  '/Subtype': '/FreeText',
  '/DA': '1 0 0 rg /HelvBld 40 Tf',
  '/DS': 'font: bold Helvetica 40pt; text-align:center; margin:0pt; line-height:46pt; color:#333333',
  '/M': "D:20120316163217-07'00'",
  '/RC': '<?xml version="1.0"?><body xmlns:xfa="http://www.xfa.org/schema/xfa-data/1.0/" xfa:contentType="text/html" xfa:APIVersion="BluebeamPDFRevu:10.0.0" xfa:spec="2.2.0" style="font:bold Helvetica 40pt; text-align:center; margin:0pt; line-height:46pt; color:#333333" xmlns="http://www.w3.org/1999/xhtml">APPROVED</body>',
  '/Rect': [76.90227, 671.4439, 303.3823, 713.4439],
  '/Contents': 'APPROVED',
  '/BS': {'/W': 0, '/S': '/S', '/Type': '/Border'},
  '/AP': {'/N': IndirectObject(11, 0)},
  '/NM': 'OQBPPTQDJECIEMHN'
}
```

For dynamic date/time stamps such as `Date.pdf` and `DateTime.pdf`, the `/Contents` and `/RC` fields contain placeholder macros such as `&[Date]` and `&[Time]` evaluated by Revu upon placement.

---

## 5. Markup Export/Import Formats (`.bax`) & Form Data (`FormImport` / `FormExport`)

* **Markup Export (.bax)**: Standardized XML or FDF/XFDF container format exported via the Markups List panel, encapsulating annotation coordinates, author, status, custom columns, and replies.
* **Form Data (`FormImport` / `FormExport`)**: FDF (Forms Data Format) and XFDF (XML Forms Data Format) supported by Bluebeam Revu for importing and exporting interactive PDF form field data (`/AcroForm`, `/Fields`).

---

## 6. Administrator CLI (`PbMngr5.exe`) Switches & Capabilities

Per the extracted documentation in `BluebeamAdministrator.chm` (`Command Line Options.htm`), the command-line administration utility `PbMngr5.exe` (located at `C:\Program Files\Bluebeam Software\Bluebeam Revu\21\Revu\PbMngr5.exe`) supports the following parameters:

* `/register <serial> <product_key>`: Re-registers the product with a different license (e.g., Enterprise licenses).
* `/setup`: Applies deployment settings. Note that values must be specified for all options or settings revert to defaults, except for `/NCPATH`, `/JOPATH`, and `/PREFSPATH`.
* `/DVON`: Makes Bluebeam Revu the default PDF editor.
* `/DVON32`: Makes Bluebeam Revu 32-bit the default PDF editor.
* `/DVOFF`: Resets the default PDF editor.
* `/IF:<flags>`: Bitwise flags to install plugins (additive sum):
  * Office (Word, Excel, Outlook, PowerPoint): `1`
  * AutoCAD: `2`
  * AutoCAD LT: `4`
  * SolidWorks: `8`
  * Revit (also ties to Navisworks): `16`
  * Internet Explorer: `32`
  * ProjectWise: `64`
  * Outlook: `128`
  * SketchUp: `256`
  * *Note*: Summing all plugins yields `1023`.
* `/DPS:[A4 or Letter]`: Sets default page size for the Bluebeam PDF printer.
* `/NCPATH:<path>`: Sets Network Configuration path.
* `/JOPATH:<path>`: Sets Job Options path.
* `/PREFSPATH:<path>`: Path to a Bluebeam Revu preferences setup file (`RevuPreferences.xml`).
* `/ANALYTICS`: Enables usage data telemetry.
* `/QLINKON` / `/QLINKOFF`: Enables or disables the Quantity Link plugin for Excel.
* `/latest`: Uses the latest installed version of Bluebeam Administrator.

### Preferences Merging Rules
When deploying preference XML files (`RevuPreferences.xml`), Revu merges settings only if:
1. The modified date of the deployed preferences file is newer than the local `UserPreferences.xml`.
2. The root element includes `Merge="True"`:
   ```xml
   <RevuPreferenceDictionary Version="1" Merge="True">
     <DocManSys>
       <ToolbarIntegrationOnlyx64.>True</ToolbarIntegrationOnlyx64.>
     </DocManSys>
   </RevuPreferenceDictionary>
   ```
