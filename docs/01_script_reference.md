# Bluebeam Script Reference: Primary-Source Compilation

This document provides an exhaustive, primary-source compilation of all scripting rules, syntax conventions, and script commands documented in **Bluebeam Script Reference Version 2.0.11** (`Bluebeam Script Reference.pdf`) and **Bluebeam Revu eXtreme Script Reference Version 1.0.9** (`Bluebeam Revu eXtreme Script Reference.pdf`).

---

## 1. Syntax & Scripting Rules

### General Script Structure
* **File Format & Integration**: Scripts are integrated into Bluebeam Revu eXtreme. Revu manages the files that scripts act upon. Scripts can be run on the active document or in batch mode (`Bluebeam Script Reference.pdf, p. 4`).
* **Execution & Lifecycle**: Revu automatically opens, saves, and closes PDF files depending on the mode and whether the script is set to commit changes (`Bluebeam Script Reference.pdf, p. 4`).
* **Toolbar Integration**: Scripts can be assigned to toolbar buttons. When pushed, the script runs on the active document (`Bluebeam Script Reference.pdf, p. 4`). Certain commands (such as `Email`) are only available when running scripts from within Revu (`Bluebeam Revu eXtreme Script Reference.pdf, p. 3`).
* **Syntax Format**: Bluebeam Scripts consist of a series of commands represented by single-word identifiers followed by a comma-delimited list of parameters enclosed in parentheses (`Bluebeam Script Reference.pdf, p. 4`):
  ```bci
  SetPDFSecurity("abacadabra", 193)
  ```
* **Comments**: Comments start with the `%` character. Any characters following `%` are ignored until a new line character is encountered (`Bluebeam Script Reference.pdf, p. 4`).

### Data Types
1. **Bool**: Boolean values (`true` or `false`) (`Bluebeam Script Reference.pdf, p. 4`).
2. **Number**: Either an integer or a real number (e.g., `1`, `3.5`, `0.2`) (`Bluebeam Script Reference.pdf, p. 4`).
3. **String**: Quoted list of characters (e.g., `"document.pdf"`). The escape character is `|` (`Bluebeam Script Reference.pdf, p. 4`).
4. **Name**: Unquoted list of characters containing letters and numbers only (e.g., `Print`, `View`, `Flatten`) (`Bluebeam Script Reference.pdf, p. 4`).
5. **Color**: A special string representing a color, which can be:
   * A color name such as `"Black"` or `"Red"` (`Bluebeam Script Reference.pdf, p. 4`).
   * A hex string such as `"#FF0000"` indicating Red (`Bluebeam Script Reference.pdf, p. 4`).
   * An integer containing RGB values as packed bytes where `B` (Blue) is the lowest byte (`Bluebeam Script Reference.pdf, p. 4`).
6. **Dictionary**: A special string representing a set of key/value pairs (`{"Key1":"Value1","Key2":"Value2"}`) (`Bluebeam Script Reference.pdf, p. 4`).
7. **Date**: A special string representing an ISO 8601 compliant date in UTC (`YYYY-MM-DDThh:mm:ss`) (`Bluebeam Script Reference.pdf, p. 4`).

### Page Index Conventions
* **0-based vs 1-based Indexing**:
  * Page index parameters for insertion (`InsertBlankPages`, `InsertPages` where `0` is before the first page) are **0-based** (`Bluebeam Script Reference.pdf, p. 14, 15`), while markup and page query commands (`MarkupCopy`, `MarkupGet`, `PageRotateGet`, `PageSize`) use `1` for the first page in their examples (`Bluebeam Script Reference.pdf, p. 15-21`). (Verified against live `ScriptEngine.exe` in `02_binary_and_dotnet_surface.md`).
  * Page range strings (such as `pPageRange`, `1,2,10-20`, or `-1` for all pages) are **1-based** (`Bluebeam Script Reference.pdf, p. 7, 20`).

### Markups Property Dictionary Keys (`Bluebeam Script Reference.pdf, p. 5`)
Commands that return or accept string dictionaries of markup properties (`MarkupGet`, `MarkupGetEx`, `MarkupGetExList`, `MarkupSet`, `Search`) support these exact keys:
* `type`: The type of markup such as square or polygon (`Bluebeam Script Reference.pdf, p. 5`).
* `page`: The page index that the markup occurs on (`Bluebeam Script Reference.pdf, p. 5`).
* `author`: The author of the markup (`Bluebeam Script Reference.pdf, p. 5`).
* `subject`: The subject of the markup (`Bluebeam Script Reference.pdf, p. 5`).
* `comment`: The comment of the markup (`Bluebeam Script Reference.pdf, p. 5`).
* `color`: The color of the markup (`Bluebeam Script Reference.pdf, p. 5`).
* `colorfill`: The fill color of the markup (`Bluebeam Script Reference.pdf, p. 5`).
* `colortext`: The text color of the markup (`Bluebeam Script Reference.pdf, p. 5`).
* `opacity`: The opacity of the markup from `0` to `1` (`Bluebeam Script Reference.pdf, p. 5`).
* `opacityfill`: The fill opacity of the markup from `0` to `1` (`Bluebeam Script Reference.pdf, p. 5`).
* `rotation`: The rotation of the markup in degrees from `0` to `360` (`Bluebeam Script Reference.pdf, p. 5`).
* `parent`: The markup ID of the markup's parent, used for parent/child relationships of grouped markups (`Bluebeam Script Reference.pdf, p. 5`).
* `grouped`: Boolean value indicating if the markup is grouped (`Bluebeam Script Reference.pdf, p. 5`).
* `status`: The status of the markup; valid states in the built-in Review model are `"Accepted"`, `"Rejected"`, `"Cancelled"`, `"Completed"`, and `"None"` (`Bluebeam Script Reference.pdf, p. 5`).
* `checked`: Boolean value indicating that the markup is checked or unchecked (`Bluebeam Script Reference.pdf, p. 5`).
* `locked`: Boolean value indicating that the markup is locked or unlocked (`Bluebeam Script Reference.pdf, p. 5`).
* `datecreated`: The creation date of the markup (`Bluebeam Script Reference.pdf, p. 5`).
* `datemodified`: The modified date of the markup (`Bluebeam Script Reference.pdf, p. 5`).
* `linewidth`: The width of the line in points (`72` points = `1` inch; typical range `0` to `12`) (`Bluebeam Script Reference.pdf, p. 5`).
* `linestyle`: The style of the line; valid styles are `"solid"`, `"dashed1"`, `"dashed2"`, `"dashed3"`, `"dashed4"`, `"dashed5"`, `"dashed6"`, `"cloudy1"`, and `"cloudy2"` (`Bluebeam Script Reference.pdf, p. 5`).
* `x`: The X coordinate of the markup in points (`72` points = `1` inch) (`Bluebeam Script Reference.pdf, p. 5`).
* `y`: The Y coordinate of the markup in points (`72` points = `1` inch) (`Bluebeam Script Reference.pdf, p. 5`).
* `width`: The width of the markup in points (`72` points = `1` inch) (`Bluebeam Script Reference.pdf, p. 5`).
* `height`: The height of the markup in points (`72` points = `1` inch) (`Bluebeam Script Reference.pdf, p. 5`).
* `space`: The space defined in the PDF that the markup resides in (read-only) (`Bluebeam Script Reference.pdf, p. 5`).
* `layer`: The layer that the markup is assigned to (read-only) (`Bluebeam Script Reference.pdf, p. 5`).
* `captureCount`: The number of capture images and video attached to the markup (read-only) (`Bluebeam Script Reference.pdf, p. 5`).

---

## 2. Exhaustive Command Reference

### BalancePages
* **Description**: Inserts blank pages into the active document to balance the total number of pages to an odd, even, specific count, or specific page division (`Bluebeam Script Reference.pdf, p. 5`).
* **Parameters**:
  * `pType` [String]: Specifies how blank pages are inserted at the end of the PDF file:
    * `"even"` = Inserts one page if needed to make count even (`Bluebeam Script Reference.pdf, p. 6`).
    * `"odd"` = Inserts one page if needed to make count odd (`Bluebeam Script Reference.pdf, p. 6`).
    * `n` = Inserts pages to make page count divisible by `n` (`n` is a number) (`Bluebeam Script Reference.pdf, p. 6`).
    * `-n` = Inserts pages to make page count at least `n` pages (`n` is a number) (`Bluebeam Script Reference.pdf, p. 6`).
  * `pWidth` [String, Optional]: Width of page in inches (`"last"` means width of last page) (`Bluebeam Script Reference.pdf, p. 6`).
  * `pHeight` [String, Optional]: Height of page in inches (`"last"` means height of last page) (`Bluebeam Script Reference.pdf, p. 6`).
  * `pStyle` [Number, Optional]: Page Style:
    * `0` = Blank (`Bluebeam Script Reference.pdf, p. 6`)
    * `1` = Notebook (`Bluebeam Script Reference.pdf, p. 6`)
    * `2` = 1/8" Grid (`Bluebeam Script Reference.pdf, p. 6`)
    * `3` = 1/4" Grid (`Bluebeam Script Reference.pdf, p. 6`)
    * `4` = Engineering Grid (`Bluebeam Script Reference.pdf, p. 6`)
    * `5` = 0.5 cm Grid (`Bluebeam Script Reference.pdf, p. 6`)
    * `6` = 1 cm Grid (`Bluebeam Script Reference.pdf, p. 6`)
    * `7` = 1/2" Isometric Grid (`Bluebeam Script Reference.pdf, p. 6`)
    * `8` = 0.5 cm Isometric Grid (`Bluebeam Script Reference.pdf, p. 6`)
* **Examples**:
  ```bci
  BalancePages("even")
  BalancePages(4, 8.5, 11, 1)
  ```
  (`Bluebeam Script Reference.pdf, p. 6`)

---

### Batch
* **Description**: Runs a script file on each specified PDF file. Any set of either PDF files or folders containing PDF files may be passed as arguments. The filename of each PDF file is passed as `arg0` to the script (`Bluebeam Script Reference.pdf, p. 6`).
* **Parameters**:
  * `pScriptPath` [String]: Filename of the script file to run (`Bluebeam Script Reference.pdf, p. 6`).
  * `pIncludeSubFolders` [Bool]: If `true`, sub-folders are processed recursively (`Bluebeam Script Reference.pdf, p. 6`).
  * `pPath` [String]: File or directory of the PDF files to loop over (`Bluebeam Script Reference.pdf, p. 6`).
  * `pPathN` [String, Optional, ...]: File or directory of additional PDF files to loop over (`Bluebeam Script Reference.pdf, p. 6`).
* **Example**:
  ```bci
  Batch("script1.bci", "c:\\Directory")
  Batch("script1.bci", false, "c:\\Directory\\file1.pdf", "c:\\Directory\\file2.pdf")
  ```
  (`Bluebeam Script Reference.pdf, p. 6`)

---

### Close
* **Description**: Closes the active document, removing it from the top of the stack (`Bluebeam Script Reference.pdf, p. 7`).
* **Parameters**:
  * `pSave` [Bool, Optional]: Boolean value specifying whether to save the document before closing (`Bluebeam Script Reference.pdf, p. 7`).
  * `pSaveMode` [Number, Optional]: Save Mode:
    * `0` = Incremental Updates (`Bluebeam Script Reference.pdf, p. 7`)
    * `1` = Publish (`Bluebeam Script Reference.pdf, p. 7`)
    * `2` = Publish Compressed 1.5 (`Bluebeam Script Reference.pdf, p. 7`)
    * `3` = Publish Compressed 1.6 (`Bluebeam Script Reference.pdf, p. 7`)
    * `4` = Publish Compressed 1.7 (`Bluebeam Script Reference.pdf, p. 7`)
* **Examples**:
  ```bci
  Close()
  Close(true)
  Close(true, 2)
  ```
  (`Bluebeam Script Reference.pdf, p. 7`)

---

### ColorProcess
* **Description**: Converts page content colors to a color or gray scale (`Bluebeam Script Reference.pdf, p. 7`).
* **Parameters**:
  * `pStartColor` [Color]: Start color to convert source colors to (usually darker color) (`Bluebeam Script Reference.pdf, p. 7`).
  * `pEndColor` [Color]: End color to convert source colors to (usually lighter color) (`Bluebeam Script Reference.pdf, p. 7`).
  * `pScale` [Bool, Optional]: Indicates that colors should be scaled from start to end (`Bluebeam Script Reference.pdf, p. 7`).
  * `pProcessImages` [Bool, Optional]: Images should be converted to new colors (`Bluebeam Script Reference.pdf, p. 7`).
  * `pPageRange` [String, Optional]: List or range of pages to be processed (`-1` processes all pages, e.g., `"1,2,10-20"`) (`Bluebeam Script Reference.pdf, p. 7`).
* **Examples**:
  ```bci
  ColorProcess("black", "white")
  ColorProcess("Red", "white", true, true, "10-20")
  ```
  (`Bluebeam Script Reference.pdf, p. 7`)

---

### ColorProcessAnalyze
* **Description**: Analyzes content to find a list of colors in use (`Bluebeam Script Reference.pdf, p. 7`).
* **Parameters**:
  * `pPageRange` [String, Optional]: List or range of pages to be processed (`-1` processes all pages, e.g., `"1,2,10-20"`) (`Bluebeam Script Reference.pdf, p. 7`).
* **Examples**:
  ```bci
  ColorProcessAnalyze()
  ColorProcessAnalyze("10-20")
  ```
  (`Bluebeam Script Reference.pdf, p. 7`)

---

### ColorProcessModify
* **Description**: Modifies colors in the content (`Bluebeam Script Reference.pdf, p. 8`).
* **Parameters**:
  * `pColorDictionary` [String]: Color modifications as a dictionary (`Bluebeam Script Reference.pdf, p. 8`).
  * `pPageRange` [String, Optional]: List or range of pages to be processed (`-1` processes all pages) (`Bluebeam Script Reference.pdf, p. 8`).
* **Examples**:
  ```bci
  ColorProcessModify("{'#FF0000':'#00FF00'}")
  ColorProcessModify("{'#FF0000':'#00FF00'}", "10-20")
  ```
  (`Bluebeam Script Reference.pdf, p. 8`)

---

### ColumnDataGet
* **Description**: Retrieves Custom Column data associated with a particular markup, returning data for multiple columns as a string dictionary, or a single column as a string (`Bluebeam Script Reference.pdf, p. 8`).
* **Parameters**:
  * `pPageIndex` [Number]: Page Index of the markup (`Bluebeam Script Reference.pdf, p. 8`).
  * `pMarkupID` [String]: ID associated with the markup (`Bluebeam Script Reference.pdf, p. 8`).
  * `pColumn` [String, Optional, ...]: Column name(s) to retrieve (`Bluebeam Script Reference.pdf, p. 8`).
* **Examples**:
  ```bci
  ColumnDataGet(0, "NDFJKXLKJKLDFY")
  ColumnDataGet(0, "NDFJKXLKJKLDFY", "Material", "Subtotal")
  ```
  (`Bluebeam Script Reference.pdf, p. 8`)

---

### ColumnDataGetDict
* **Description**: Retrieves Custom Column data associated with a markup as a string dictionary (`Bluebeam Script Reference.pdf, p. 8`).
* **Parameters**:
  * `pPageIndex` [Number]: Page Index of the markup (`Bluebeam Script Reference.pdf, p. 8`).
  * `pMarkupID` [String]: ID associated with the markup (`Bluebeam Script Reference.pdf, p. 8`).
  * `pColumn` [String, Optional, ...]: Column name(s) (`Bluebeam Script Reference.pdf, p. 8`).
* **Examples**:
  ```bci
  ColumnDataGetDict(0, "NDFJKXLKJKLDFY")
  ColumnDataGetDict(0, "NDFJKXLKJKLDFY", "Material", "Subtotal")
  ```
  (`Bluebeam Script Reference.pdf, p. 8`)

---

### ColumnDataSet
* **Description**: Sets Custom Column data for a particular markup (`Bluebeam Script Reference.pdf, p. 8-9`).
* **Parameters**:
  * `pPageIndex` [Number]: Page Index of the markup (`Bluebeam Script Reference.pdf, p. 8`).
  * `pMarkupID` [String]: ID associated with the markup (`Bluebeam Script Reference.pdf, p. 8`).
  * `pData` [String]: Custom Column data as a string dictionary (`Bluebeam Script Reference.pdf, p. 9`).
* **Example**:
  ```bci
  ColumnDataSet(0, "NDFJKXLKJKLDFY", "{'Material':'Glass'}")
  ```
  (`Bluebeam Script Reference.pdf, p. 9`)

---

### ColumnsExport
* **Description**: Exports Custom Column definitions of the active document to an XML file (`Bluebeam Script Reference.pdf, p. 9`).
* **Parameters**:
  * `pFileName` [String]: Filename to export columns into (`Bluebeam Script Reference.pdf, p. 9`).
* **Example**:
  ```bci
  ColumnsExport('columns.xml')
  ```
  (`Bluebeam Script Reference.pdf, p. 9`)

---

### ColumnsImport
* **Description**: Imports a Custom Column definition XML file into the active document, overwriting existing custom columns (`Bluebeam Script Reference.pdf, p. 9`).
* **Parameters**:
  * `pFileName` [String]: Filename of the XML file (`Bluebeam Script Reference.pdf, p. 9`).
* **Example**:
  ```bci
  ColumnsImport("columns.xml")
  ```
  (`Bluebeam Script Reference.pdf, p. 9`)

---

### Combine
* **Description**: Combines specified files into a new PDF file that becomes the active document (`Bluebeam Script Reference.pdf, p. 9`).
* **Parameters**:
  * `pFile1` [String]: First PDF file (`Bluebeam Script Reference.pdf, p. 9`).
  * `pFile2` [String]: Second PDF file (`Bluebeam Script Reference.pdf, p. 9`).
  * `pFileN` [String, Optional, ...]: Additional PDF files (`Bluebeam Script Reference.pdf, p. 9`).
* **Example**:
  ```bci
  Combine("document1.pdf", "document2.pdf", "document3.pdf")
  Save("output.pdf")
  ```
  (`Bluebeam Script Reference.pdf, p. 9`)

---

### CreatePDFAReport
* **Description**: Generates a text report on whether a PDF file is PDF/A-1b compliant. Results are appended to the specified report file (`Bluebeam Script Reference.pdf, p. 9-10`).
* **Parameters**:
  * `pFileName` [String]: Absolute full path to the report file (`Bluebeam Script Reference.pdf, p. 10`).
* **Example**:
  ```bci
  CreatePDFAReport("C:\\pdfa\\report.txt")
  ```
  (`Bluebeam Script Reference.pdf, p. 10`)

---

### DeleteFile
* **Description**: Deletes a file from the specified location (`Bluebeam Script Reference.pdf, p. 10`).
* **Parameters**:
  * `pFileName` [String]: Filename to delete (`Bluebeam Script Reference.pdf, p. 10`).
* **Example**:
  ```bci
  DeleteFile("c:\\Directory\\Filename.pdf")
  ```
  (`Bluebeam Script Reference.pdf, p. 10`)

---

### Email (eXtreme Only)
* **Description**: Launches an Email window with the active document attached (`Bluebeam Revu eXtreme Script Reference.pdf, p. 5`).
* **Parameters**:
  * `pTo` [String, Optional]: Email address of recipient (use `;` to delimit multiple addresses) (`Bluebeam Revu eXtreme Script Reference.pdf, p. 5`).
  * `pSubject` [String, Optional]: Email subject (`Bluebeam Revu eXtreme Script Reference.pdf, p. 5`).
  * `pBody` [String, Optional]: Email body (`Bluebeam Revu eXtreme Script Reference.pdf, p. 5`).
* **Examples**:
  ```bci
  Email()
  Email("support@bluebeam.com")
  ```
  (`Bluebeam Revu eXtreme Script Reference.pdf, p. 5`)

---

### EmbedJavaScript
* **Description**: Embeds a specified JavaScript file as a document-level script in the active document (`Bluebeam Script Reference.pdf, p. 10`).
* **Parameters**:
  * `pName` [String]: Name of JavaScript Code (`Bluebeam Script Reference.pdf, p. 10`).
  * `pFile` [String]: JavaScript file to embed (`Bluebeam Script Reference.pdf, p. 10`).
* **Example**:
  ```bci
  EmbedJavaScript("File.js")
  ```
  (`Bluebeam Script Reference.pdf, p. 10`)

---

### Export
* **Description**: Exports markups in the active document to a specified output file, optionally filtered by User ID (`Bluebeam Script Reference.pdf, p. 10`).
* **Parameters**:
  * `pOutputBAX` [String, Optional]: Filename to export markups into (`Bluebeam Script Reference.pdf, p. 10`).
  * `pUserID` [String, Optional]: User ID as used in bFX File Exchange (`Bluebeam Script Reference.pdf, p. 10`).
* **Examples**:
  ```bci
  Export("output.bax")
  Export("output.bax", "12345")
  ```
  (`Bluebeam Script Reference.pdf, p. 10`)

---

### FilePropertyGet
* **Description**: Returns the value of a file property corresponding to the key passed as a parameter. In non-interactive mode, outputs straight to console without count prefix (`Bluebeam Script Reference.pdf, p. 10-11`).
* **Parameters**:
  * `pKey` [String]: Key of file property (`Bluebeam Script Reference.pdf, p. 11`).
* **Example**:
  ```bci
  FilePropertyGet("Author")
  ```
  (`Bluebeam Script Reference.pdf, p. 11`)

---

### FilePropertyList
* **Description**: Returns the keys of all file properties in the active document as a list of strings (`Bluebeam Script Reference.pdf, p. 11`).
* **Parameters**: None (`Bluebeam Script Reference.pdf, p. 11`).
* **Example**:
  ```bci
  FilePropertyList()
  ```
  (`Bluebeam Script Reference.pdf, p. 11`)

---

### FilePropertySet
* **Description**: Sets a file property in the active document based on key and value (`Bluebeam Script Reference.pdf, p. 11`).
* **Parameters**:
  * `pKey` [String]: Key of file property (`Bluebeam Script Reference.pdf, p. 11`).
  * `pValue` [String]: Desired value (`Bluebeam Script Reference.pdf, p. 11`).
* **Example**:
  ```bci
  FilePropertySet("Author", "Homer J. Simpson")
  ```
  (`Bluebeam Script Reference.pdf, p. 11`)

---

### Flatten
* **Description**: Flattens markups in the active document to be part of page content (`Bluebeam Script Reference.pdf, p. 11-12`).
* **Parameters**:
  * `pRecoverable` [Bool, Optional]: Specifies if flattening is reversible (`Bluebeam Script Reference.pdf, p. 11`).
  * `pFlags` [Number, Optional]: Specifies markup types to flatten (Default = 8191) (`Bluebeam Script Reference.pdf, p. 11`):
    * Image = 1 (`Bluebeam Script Reference.pdf, p. 11`)
    * Ellipse = 2 (`Bluebeam Script Reference.pdf, p. 11`)
    * Stamp = 4 (`Bluebeam Script Reference.pdf, p. 11`)
    * Snapshot = 8 (`Bluebeam Script Reference.pdf, p. 11`)
    * Text and Callout = 16 (`Bluebeam Script Reference.pdf, p. 12`)
    * Ink and Highlighter = 32 (`Bluebeam Script Reference.pdf, p. 12`)
    * Line and Dimension = 64 (`Bluebeam Script Reference.pdf, p. 12`)
    * Measure Area = 128 (`Bluebeam Script Reference.pdf, p. 12`)
    * Polyline = 256 (`Bluebeam Script Reference.pdf, p. 12`)
    * Polygon and Cloud = 512 (`Bluebeam Script Reference.pdf, p. 12`)
    * Rectangle = 1024 (`Bluebeam Script Reference.pdf, p. 12`)
    * Text Markups = 2048 (`Bluebeam Script Reference.pdf, p. 12`)
    * Group = 4096 (`Bluebeam Script Reference.pdf, p. 12`)
    * File Attachment = 8192 (`Bluebeam Script Reference.pdf, p. 12`)
    * Flags = 16384 (`Bluebeam Script Reference.pdf, p. 12`)
    * Notes = 32768 (`Bluebeam Script Reference.pdf, p. 12`)
    * Form Fields = 65536 (`Bluebeam Script Reference.pdf, p. 12`)
    *(Add values together)* (`Bluebeam Script Reference.pdf, p. 12`)
  * `pPageRange` [String, Optional]: Pages to flatten (`-1` for all) (`Bluebeam Script Reference.pdf, p. 12`).
  * `pLayerName` [String, Optional]: Layer Name to flatten markups to (`Bluebeam Script Reference.pdf, p. 12`).
* **Examples**:
  ```bci
  Flatten()
  Flatten(true)
  Flatten(true, 9)
  ```
  (`Bluebeam Script Reference.pdf, p. 12`)

---

### FormExport
* **Description**: Exports form data to an XML, CSV, or FDF file (`Bluebeam Script Reference.pdf, p. 12`).
* **Parameters**:
  * `pFileName` [String]: Filename (`.xml`, `.csv`, `.fdf`) (`Bluebeam Script Reference.pdf, p. 12`).
* **Example**:
  ```bci
  FormExport("formdata.fdf")
  ```
  (`Bluebeam Script Reference.pdf, p. 12`)

---

### FormImport
* **Description**: Imports an FDF file containing form data into the active document (`Bluebeam Script Reference.pdf, p. 12`).
* **Parameters**:
  * `pFileName` [String]: Filename of FDF file (`Bluebeam Script Reference.pdf, p. 12`).
* **Example**:
  ```bci
  FormImport("formdata.fdf")
  ```
  (`Bluebeam Script Reference.pdf, p. 12`)

---

### FormMerge
* **Description**: Merges form data from a set of PDF files into one XML or CSV file (`Bluebeam Script Reference.pdf, p. 12-13`).
* **Parameters**:
  * `pFileName` [String]: Filename (`.xml` or `.csv`) (`Bluebeam Script Reference.pdf, p. 13`).
  * `pIncludeSubFolders` [Bool]: Process sub-folders recursively (`Bluebeam Script Reference.pdf, p. 13`).
  * `pPath` [String]: File or directory of PDF files (`Bluebeam Script Reference.pdf, p. 13`).
  * `pPathN` [String, Optional, ...]: Additional paths (`Bluebeam Script Reference.pdf, p. 13`).

---

### HeaderAndFooter
* **Description**: Applies headers and footers using dynamic codes (`Bluebeam Script Reference.pdf, p. 13-14`).
* **Substitution Codes**:
  * Page Index: `<<1>>`, `<<1 of n>>`, `<<1/n>>`, `<<Page 1>>`, `<<Page 1 of n>>` (`Bluebeam Script Reference.pdf, p. 13`).
  * Date Codes: `<<M/d>>`, `<<M/d/yy>>`, `<<M/d/yyyy>>`, `<<MM/dd/yy>>`, `<<MM/dd/yyyy>>`, `<<d/M/yy>>`, `<<d/M/yyyy>>`, `<<dd/MM/yy>>`, `<<dd/MM/yyyy>>`, `<<MM/yy>>`, `<<MM/yyyy>>`, `<<ddd MMM d, yyyy>>`, `<<dddd MMMM d, yyyy>>`, `<<MM/dd/yyyy h:mm tt>>`, `<<dd/MM/yyyy HH:mm>>` (`Bluebeam Script Reference.pdf, p. 13`).
  * Bates Numbering: `<<Bates Number#Digits#Start#Prefix#Suffix>>` (`Bluebeam Script Reference.pdf, p. 13`).
  * File Properties: `<<Title>>`, `<<Author>>`, `<<Client>>`, `<<FileName>>`, `<<Path>>`, `<<PageLabel>>` (`Bluebeam Script Reference.pdf, p. 13`).
* **Parameters**:
  * `pTopLeft`, `pTopCenter`, `pTopRight`, `pBottomLeft`, `pBottomCenter`, `pBottomRight` [String] (`Bluebeam Script Reference.pdf, p. 13`).
  * `pMarginLeft`, `pMarginTop`, `pMarginRight`, `pMarginBottom` [Number, Optional] (points) (`Bluebeam Script Reference.pdf, p. 13`).
  * `pFont` [String, Optional], `pSize` [Number, Optional] (`Bluebeam Script Reference.pdf, p. 13`).
  * `pBold`, `pItalic`, `pUnderline` [Bool, Optional] (`Bluebeam Script Reference.pdf, p. 13`).
  * `pColor` [Color, Optional], `pFitToContent` [Bool, Optional] (`Bluebeam Script Reference.pdf, p. 13`).
  * `pBatesOffset` [Number, Optional], `pBatesKey` [String, Optional] (`Bluebeam Script Reference.pdf, p. 13-14`).
  * `pPageRange` [String, Optional] (`Bluebeam Script Reference.pdf, p. 14`).

---

### Import
* **Description**: Imports markups from a list of BAX or PDF files into the active document (`Bluebeam Script Reference.pdf, p. 14`).
* **Parameters**:
  * `pBAXorPDF` [String, ...]: Filename(s) of BAX or PDF files (`Bluebeam Script Reference.pdf, p. 14`).
* **Example**:
  ```bci
  Import("markups1.bax", "markups2.bax")
  ```
  (`Bluebeam Script Reference.pdf, p. 14`)

---

### InsertBlankPages
* **Description**: Inserts new blank pages into the active document (`Bluebeam Script Reference.pdf, p. 14`).
* **Parameters**:
  * `pIndex` [Number]: Page Index to insert pages after (`0` is before first page) (`Bluebeam Script Reference.pdf, p. 14`).
  * `pWidth` [Number]: Width in inches (`Bluebeam Script Reference.pdf, p. 14`).
  * `pHeight` [Number]: Height in inches (`Bluebeam Script Reference.pdf, p. 14`).
  * `pCount` [Number, Optional]: Number of pages (`Bluebeam Script Reference.pdf, p. 14`).
  * `pStyle` [Number, Optional]: Page Style (`0-8`) (`Bluebeam Script Reference.pdf, p. 14`).

---

### InsertPages
* **Description**: Inserts a PDF file into the active document with options for bookmarks, attachments, properties, and layers (`Bluebeam Script Reference.pdf, p. 15`).
* **Parameters**:
  * `pIndex` [Number]: Page Index (`0` before first page) (`Bluebeam Script Reference.pdf, p. 15`).
  * `pFileName` [String]: Document filename (`Bluebeam Script Reference.pdf, p. 15`).
  * `pBookmarks` [Bool, Optional]: Insert bookmarks from inserted file (default `false`) (`Bluebeam Script Reference.pdf, p. 15`).
  * `pAttachments` [Bool, Optional]: Insert file attachments from inserted file (default `false`) (`Bluebeam Script Reference.pdf, p. 15`).
  * `pProperties` [Bool, Optional]: Merge document properties from inserted file (default `false`) (`Bluebeam Script Reference.pdf, p. 15`).
  * `pLayers` [Bool, Optional]: Merge document layers from inserted file (default `false`) (`Bluebeam Script Reference.pdf, p. 15`).
  * `pUseFileName` [Bool, Optional]: Use file name as Page Label (default `false`) (`Bluebeam Script Reference.pdf, p. 15`).
* **Examples**:
  ```bci
  InsertPages(0, "Document.pdf")
  InsertPages(0, "Document.pdf", true, true, true, true)
  ```
  (`Bluebeam Script Reference.pdf, p. 15`)

---

### MarkupCaptureExport
* **Description**: Exports photos and videos attached to a markup (`Bluebeam Script Reference.pdf, p. 15`).
* **Parameters**:
  * `pPageIndex` [Number]: Page Index of the markup (`Bluebeam Script Reference.pdf, p. 15`).
  * `pMarkupID` [String]: ID associated with the markup (`Bluebeam Script Reference.pdf, p. 15`).
  * `pFolder` [String, Optional]: Folder path to export capture media into (`Bluebeam Script Reference.pdf, p. 15`).

---

### MarkupCopy
* **Description**: Returns an XML string containing raw markup data that can be passed into `MarkupPaste` to be placed at a new location. If the markup is the parent of a group, the whole group is copied (`Bluebeam Script Reference.pdf, p. 15`).
* **Parameters**:
  * `pPageIndex` [Number]: Page Index of the markup (`Bluebeam Script Reference.pdf, p. 15`).
  * `pMarkupID` [String]: ID associated with the markup (`Bluebeam Script Reference.pdf, p. 15`).
* **Example**:
  ```bci
  MarkupCopy(1, "YIBKQIOZSROMNDGD")
  ```
  (`Bluebeam Script Reference.pdf, p. 15`)

---

### MarkupDelete
* **Description**: Deletes a particular markup from the active document (`Bluebeam Script Reference.pdf, p. 15-16`).
* **Parameters**:
  * `pPageIndex` [Number]: Page Index of the markup (`Bluebeam Script Reference.pdf, p. 16`).
  * `pMarkupID` [String]: ID associated with the markup (`Bluebeam Script Reference.pdf, p. 16`).
* **Example**:
  ```bci
  MarkupDelete(1, "YIBKQIOZSROMNDGD")
  ```
  (`Bluebeam Script Reference.pdf, p. 16`)

---

### MarkupGet / MarkupGetEx / MarkupGetExList
* **Description**:
  * `MarkupGet`: Retrieves properties associated with a markup as a string dictionary (multiple properties) or single string (`Bluebeam Script Reference.pdf, p. 16`).
  * `MarkupGetEx`: Retrieves properties including custom properties for a markup (`Bluebeam Script Reference.pdf, p. 16`).
  * `MarkupGetExList`: Retrieves all properties including custom properties for all markups on a given page (`Bluebeam Script Reference.pdf, p. 16`).
* **Parameters**:
  * `pPageIndex` [Number]: Page Index of the markup (`Bluebeam Script Reference.pdf, p. 16`).
  * `pMarkupID` [String]: ID associated with the markup (omitted in `MarkupGetExList`) (`Bluebeam Script Reference.pdf, p. 16`).
  * `pProperty` [String, Optional, ...]: Specific markup property name(s) to retrieve (`Bluebeam Script Reference.pdf, p. 16`).
* **Examples**:
  ```bci
  MarkupGet(1, "YIBKQIOZSROMNDGD")
  MarkupGet(1, "YIBKQIOZSROMNDGD", "subject")
  MarkupGetEx(1, "YIBKQIOZSROMNDGD", "type", "comment")
  MarkupGetExList(1)
  ```
  (`Bluebeam Script Reference.pdf, p. 16-17`)

---

### MarkupList
* **Description**: Retrieves the list of markup IDs associated with a particular page (`Bluebeam Script Reference.pdf, p. 17`).
* **Parameters**:
  * `pPageIndex` [Number]: Page Index (`Bluebeam Script Reference.pdf, p. 17`).
* **Example**:
  ```bci
  MarkupList(1)
  ```
  (`Bluebeam Script Reference.pdf, p. 17`)

---

### MarkupPaste
* **Description**: Pastes a markup passed in as raw XML (from `MarkupCopy`) at the provided coordinates. Returns a list of markup IDs of the pasted markups (`Bluebeam Script Reference.pdf, p. 17`).
* **Parameters**:
  * `pPageIndex` [Number]: Page Index of paste destination (`Bluebeam Script Reference.pdf, p. 17`).
  * `pXML` [String]: XML string containing raw markup data (`Bluebeam Script Reference.pdf, p. 17`).
  * `pX` [Number]: X coordinate of paste location in points (`72` points per inch) (`Bluebeam Script Reference.pdf, p. 17`).
  * `pY` [Number]: Y coordinate of paste location in points (`72` points per inch) (`Bluebeam Script Reference.pdf, p. 17`).
* **Example**:
  ```bci
  MarkupPaste(1, "<...Raw XML...>", 144, 72)
  ```
  (`Bluebeam Script Reference.pdf, p. 17`)

---

### MarkupSet
* **Description**: Sets properties for a particular markup using a string dictionary containing key/value pairs (`Bluebeam Script Reference.pdf, p. 17`).
* **Parameters**:
  * `pPageIndex` [Number]: Page Index of the markup (`Bluebeam Script Reference.pdf, p. 17`).
  * `pMarkupID` [String]: ID associated with the markup (`Bluebeam Script Reference.pdf, p. 17`).
  * `pData` [String]: Markup properties as a string dictionary (`Bluebeam Script Reference.pdf, p. 17`).
* **Example**:
  ```bci
  MarkupSet(1, "YIBKQIOZSROMNDGD", "{'comment':'The color is red','color':'#FF0000'}")
  ```
  (`Bluebeam Script Reference.pdf, p. 17`)

---

### MarkupStatusGet / MarkupStatusSet
* **Description**: Gets or sets statuses for a particular markup, supporting user-defined state models in addition to the built-in `"Review"` state model (`Bluebeam Script Reference.pdf, p. 17-18`).
* **Parameters**:
  * `pPageIndex` [Number]: Page Index of the markup (`Bluebeam Script Reference.pdf, p. 18`).
  * `pMarkupID` [String]: ID associated with the markup (`Bluebeam Script Reference.pdf, p. 18`).
  * `pStateModel` [String] (`MarkupStatusSet` only): State Model key (e.g., `"Review"`) (`Bluebeam Script Reference.pdf, p. 18`).
  * `pState` [String] (`MarkupStatusSet` only): State value (e.g., `"Accepted"`) (`Bluebeam Script Reference.pdf, p. 18`).
* **Examples**:
  ```bci
  MarkupStatusGet(1, "YIBKQIOZSROMNDGD")
  MarkupStatusSet(1, "YIBKQIOZSROMNDGD", "Review", "Accepted")
  ```
  (`Bluebeam Script Reference.pdf, p. 18`)

---

### MarkupThumbnail
* **Description**: Generates a thumbnail image (`.bmp`, `.png`, `.jpg`, etc.) of a markup or markup group (`Bluebeam Script Reference.pdf, p. 18`).
* **Parameters**:
  * `pPageIndex` [Number]: Page Index of the markup (`Bluebeam Script Reference.pdf, p. 18`).
  * `pMarkupID` [String]: ID associated with the markup (`Bluebeam Script Reference.pdf, p. 18`).
  * `pWidth` [Number]: Desired width in pixels of output thumbnail image (`Bluebeam Script Reference.pdf, p. 18`).
  * `pHeight` [Number]: Desired height in pixels of output thumbnail image (`Bluebeam Script Reference.pdf, p. 18`).
  * `pPercentage` [Number]: Desired percentage of the thumbnail that the markup should cover (`0.0` to `1.0`) (`Bluebeam Script Reference.pdf, p. 18`).
  * `pIncludePageContent` [Bool]: Whether the thumbnail includes background page content (`Bluebeam Script Reference.pdf, p. 18`).
  * `pFilename` [String]: Filename of desired output thumbnail image (`Bluebeam Script Reference.pdf, p. 18`).
  * `pIncludeAllMarkups` [Bool, Optional]: Whether all markups on the page should be included (`Bluebeam Script Reference.pdf, p. 18`).
* **Example**:
  ```bci
  MarkupThumbnail(1, "YIBKQIOZSROMNDGD", 256, 256, 0.5, true, "thumb.png", false)
  ```
  (`Bluebeam Script Reference.pdf, p. 18`)

---

### New
* **Description**: Creates a new blank PDF file using specified width, height, page count, and style. Defaults: `8.5` x `11` inches, count `1`, style `0` (Blank) (`Bluebeam Script Reference.pdf, p. 18-19`).
* **Parameters**:
  * `pWidth` [Number, Optional]: Width of page in inches (`Bluebeam Script Reference.pdf, p. 19`).
  * `pHeight` [Number, Optional]: Height of page in inches (required if `pWidth` is specified) (`Bluebeam Script Reference.pdf, p. 19`).
  * `pCount` [Number, Optional]: Number of pages to create (`Bluebeam Script Reference.pdf, p. 19`).
  * `pStyle` [Number, Optional]: Page Style (`0` = Blank, `1` = Notebook, `2` = 1/8" Grid, `3` = 1/4" Grid, `4` = Engineering Grid, `5` = 0.5 cm Grid, `6` = 1 cm Grid, `7` = 1/2" Isometric Grid, `8` = 0.5 cm Isometric Grid) (`Bluebeam Script Reference.pdf, p. 19`).
* **Examples**:
  ```bci
  New()
  New(8.5, 11)
  New(8.5, 11, 10, 3)
  ```
  (`Bluebeam Script Reference.pdf, p. 19`)

---

### Open / OpenImage
* **Description**:
  * `Open`: Opens the specified PDF file and pushes it to the top of the document stack making it active (`Bluebeam Script Reference.pdf, p. 19`).
  * `OpenImage`: Converts and combines one or more image files to PDF and pushes the document to the top of the stack (`Bluebeam Script Reference.pdf, p. 19`).
* **Parameters**:
  * `Open(pFilename, pPassword)`: `pFilename` [String], `pPassword` [String, Optional] (`Bluebeam Script Reference.pdf, p. 19`).
  * `OpenImage(pImage1, pImageN, ...)`: `pImage1` [String], `pImageN` [String, Optional, ...] (`Bluebeam Script Reference.pdf, p. 19`).
* **Examples**:
  ```bci
  Open("document.pdf")
  Open("document.pdf", "abacadabra")
  OpenImage("drawing.tiff", "scan.png", "photo.jpg")
  ```
  (`Bluebeam Script Reference.pdf, p. 19`)

---

### PageCount / PageDelete / PageExtract / PageRotate / PageRotateGet / PageSize
* **PageCount**:
  * **Description**: Returns the number of pages in the active document. In non-interactive mode, outputs the result straight to the console (`Bluebeam Script Reference.pdf, p. 19-20`).
  * **Parameters**: None (`Bluebeam Script Reference.pdf, p. 20`).
* **PageDelete**:
  * **Description**: Deletes pages from the current document. Cannot delete all pages (`Bluebeam Script Reference.pdf, p. 20`).
  * **Parameters**: `pPageRange` [String] (e.g., `"1,2,10-20"`) (`Bluebeam Script Reference.pdf, p. 20`).
* **PageExtract**:
  * **Description**: Extracts pages from the currently active PDF document (`Bluebeam Script Reference.pdf, p. 20`).
  * **Parameters**:
    * `pPageRange` [String]: List or range of pages (`-1` extracts all pages, e.g., `"1,2,10-20"`) (`Bluebeam Script Reference.pdf, p. 20`).
    * `pFileNameOrDirectory` [String]: Filename or directory to save extracted pages to (`Bluebeam Script Reference.pdf, p. 20`).
    * `pPrefix` [String, Optional]: Filename prefix (`Bluebeam Script Reference.pdf, p. 20`).
    * `pSuffix` [String, Optional]: Filename suffix (`Bluebeam Script Reference.pdf, p. 20`).
* **PageRotate**:
  * **Description**: Rotates active document pages by 90-degree increments (`Bluebeam Script Reference.pdf, p. 20-21`).
  * **Parameters**:
    * `pRotations` [Number]: Degrees to rotate pages by (must be a multiple of `90`, e.g., `90`, `-90`, `180`) (`Bluebeam Script Reference.pdf, p. 20`).
    * `pPortrait` [Bool, Optional]: Include portrait pages (default `true`) (`Bluebeam Script Reference.pdf, p. 20`).
    * `pLandscape` [Bool, Optional]: Include landscape pages (default `true`) (`Bluebeam Script Reference.pdf, p. 20`).
    * `pPageRange` [String, Optional]: Pages to rotate (`-1` for all) (`Bluebeam Script Reference.pdf, p. 20-21`).
* **PageRotateGet**:
  * **Description**: Returns page rotation in degrees as an integer for the given page index (`Bluebeam Script Reference.pdf, p. 21`).
  * **Parameters**: `pIndex` [Number] (`Bluebeam Script Reference.pdf, p. 21`).
* **PageSize**:
  * **Description**: Returns page width and height as a string list for the given page index. In non-interactive mode, outputs straight to console (`Bluebeam Script Reference.pdf, p. 21`).
  * **Parameters**: `pIndex` [Number] (`Bluebeam Script Reference.pdf, p. 21`).

---

### Print / PrintToFile
* **Description**: Prints the active document to a physical printer (`Print`) or file (`PrintToFile`). Only 3 overload syntaxes are supported: 0 args (or 1 arg for `PrintToFile`), printer-only, or all 9 (or 10) parameters (`Bluebeam Script Reference.pdf, p. 21-22`).
* **Parameters**:
  * `pFileName` [String] (`PrintToFile` first parameter only): Output file path (`Bluebeam Script Reference.pdf, p. 22`).
  * `pPrinter` [String, Optional]: Name of printer (`Bluebeam Script Reference.pdf, p. 21`).
  * `pPageSize` [String, Optional]: Page size name on printer (e.g., `"letter"`) (`Bluebeam Script Reference.pdf, p. 21`).
  * `pLandscape` [Bool, Optional]: `true` for landscape, `false` for portrait (`Bluebeam Script Reference.pdf, p. 21`).
  * `pPageRange` [String, Optional]: Page range (`-1` for all) (`Bluebeam Script Reference.pdf, p. 21`).
  * `pAutoRotateAndCenter` [Number, Optional]: `-1` = Autorotate and center -90, `0` = No autorotate and center, `1` = Autorotate and center 90 (`Bluebeam Script Reference.pdf, p. 21`).
  * `pScaleType` [Number, Optional]: `0` = None, `1` = Fit to Paper, `2` = Shrink large Images, `3` = Custom (`Bluebeam Script Reference.pdf, p. 21-22`).
  * `pCustomScale` [Number, Optional]: Custom scale factor (e.g., `0.5` = 50%) (`Bluebeam Script Reference.pdf, p. 22`).
  * `pDim` [Bool, Optional]: Dim content when printing (`Bluebeam Script Reference.pdf, p. 22`).
  * `pCopies` / `pNumberOfCopies` [Number, Optional]: Number of copies (`Bluebeam Script Reference.pdf, p. 22`).

---

### ReduceFileSize
* **Description**: Reduces file size of the active document (`Bluebeam Script Reference.pdf, p. 22-23`).
* **Parameters**:
  * `pReduceImageLevel` [String, Optional]: Compression ratio (`"Low"`, `"Medium"`, or `"High"`; default `"Low"`) (`Bluebeam Script Reference.pdf, p. 23`).
  * `pImageDPI` [Number, Optional]: Maximum image DPI (default `150`) (`Bluebeam Script Reference.pdf, p. 23`).
  * `pDropFonts` [Bool, Optional]: Drop embedded fonts (default `true`) (`Bluebeam Script Reference.pdf, p. 23`).
  * `pDropMiscellaneous` [Bool, Optional]: Drop metadata, thumbnails, private data, unused resources (default `true`) (`Bluebeam Script Reference.pdf, p. 23`).
  * `pCompressAllStreams` [Bool, Optional]: Compress all streams (default `true`) (`Bluebeam Script Reference.pdf, p. 23`).
* **Examples**:
  ```bci
  ReduceFileSize()
  ReduceFileSize("High", 150, true, true, true)
  ```
  (`Bluebeam Script Reference.pdf, p. 23`)

---

### Repair
* **Description**: Runs a repair process on the active document using 8 boolean options (`Bluebeam Script Reference.pdf, p. 23`).
* **Parameters**:
  * `pFixStripedImages` [Bool]: Groups neighboring image stripes into a single image (`Bluebeam Script Reference.pdf, p. 23`).
  * `pCombineStripedImages` [Bool]: Merges groups of thin adjacent images into one image (`Bluebeam Script Reference.pdf, p. 23`).
  * `pOptimizeSolidColorImages` [Bool]: Converts single-color images into vector rectangles (`Bluebeam Script Reference.pdf, p. 23`).
  * `pProcessMasks` [Bool]: Fixes AutoCAD files with blend modes and masks (`Bluebeam Script Reference.pdf, p. 23`).
  * `pRemoveTextClipping` [Bool]: Fixes AutoCAD files with text clipping problems (`Bluebeam Script Reference.pdf, p. 23`).
  * `pSimplifyClippingPaths` [Bool]: Fixes Revit files with text clipping problems (`Bluebeam Script Reference.pdf, p. 23`).
  * `pRepairFontIssues` [Bool]: Fixes issues with fonts (`Bluebeam Script Reference.pdf, p. 23`).
  * `pRepairPageContent` [Bool]: Removes invalid and empty page content objects (`Bluebeam Script Reference.pdf, p. 23`).
* **Example**:
  ```bci
  Repair(true, true, true, true, true, true, true, true)
  ```
  (`Bluebeam Script Reference.pdf, p. 23`)

---

### ReplacePages / ReversePages / Save / SaveAs (eXtreme) / SaveAsPDFA / SaveAsText
* **ReplacePages**:
  * **Description**: Replaces pages in the current document with pages from the source document (`Bluebeam Script Reference.pdf, p. 23`).
  * **Parameters**:
    * `pSourceFileName` [String]: Source PDF path (`Bluebeam Script Reference.pdf, p. 23`).
    * `pSourcePages` [String]: Source page range (`-1` for all) (`Bluebeam Script Reference.pdf, p. 23`).
    * `pPagesToReplace` [String]: Target page range (`-1` for all) (`Bluebeam Script Reference.pdf, p. 23`).
    * `pContentOnly` [Bool, Optional]: If `true`, replaces only page content while preserving markups and hyperlinks (`Bluebeam Script Reference.pdf, p. 23`).
* **ReversePages**:
  * **Description**: Reverses all pages in the document (`Bluebeam Script Reference.pdf, p. 24`).
  * **Parameters**: None (`Bluebeam Script Reference.pdf, p. 24`).
* **Save**:
  * **Description**: Saves the active document over itself (no args) or to a specified file/directory (`Bluebeam Script Reference.pdf, p. 24`).
  * **Parameters**:
    * `pFileName` [String, Optional]: Destination path (`Bluebeam Script Reference.pdf, p. 24`).
    * `pSaveMode` [Number, Optional]: `0` = Incremental Updates, `1` = Publish, `2` = Publish Compressed 1.5, `3` = Publish Compressed 1.6, `4` = Publish Compressed 1.7 (`Bluebeam Script Reference.pdf, p. 24`).
* **SaveAs (Interactive / eXtreme Only)**:
  * **Description**: Launches the interactive Save As window (`Bluebeam Revu eXtreme Script Reference.pdf, p. 13`).
  * **Parameters**: `pExt` [String, Optional]: `"pdf"`, `"txt"`, `"jpeg"`, `"gif"`, `"bmp"`, `"png"`, `"tiff"`, `"docx"`, `"doc"`, `"rtf"`, `"html"`, `"xlsx"`, `"xls"`, or `"pptx"` (`Bluebeam Revu eXtreme Script Reference.pdf, p. 13`).
* **SaveAsPDFA**:
  * **Description**: Converts the current PDF document into a PDF/A-1b document (`Bluebeam Script Reference.pdf, p. 24`).
  * **Parameters**: `pFileName` [String, Optional] (`Bluebeam Script Reference.pdf, p. 24`).
* **SaveAsText**:
  * **Description**: Saves text in pages from the currently active PDF document (`Bluebeam Script Reference.pdf, p. 24-25`).
  * **Parameters**: `pPageRange` [String], `pFileName` [String], `pPrefix` [String, Optional], `pSuffix` [String, Optional] (`Bluebeam Script Reference.pdf, p. 24-25`).

---

### Script / Search / SetOpenPassword / SetPDFSecurity / SplitPages / Stamp / StateModel* / Thumbnail / Unflatten / UnlockPDFA / UserName* / View
* **Script**:
  * **Description**: Runs the specified script file, substituting `arg0`..`argN` at runtime (`Bluebeam Script Reference.pdf, p. 25`).
  * **Parameters**: `pScriptPath` [String], `Arg0` [String, Optional], `ArgN` [String, Optional, ...] (`Bluebeam Script Reference.pdf, p. 25`).
* **Search**:
  * **Description**: Searches text in the underlying PDF content and optionally applies text-based markups to results. Returns a list of markup IDs (`Bluebeam Script Reference.pdf, p. 25`).
  * **Parameters**:
    * `pTerm` [String]: Search term (`Bluebeam Script Reference.pdf, p. 25`).
    * `pCaseSensitive` [Bool, Optional]: Match case (`Bluebeam Script Reference.pdf, p. 25`).
    * `pWholeWordOnly` [Bool, Optional]: Match whole word only (`Bluebeam Script Reference.pdf, p. 25`).
    * `pMarkup` [String, Optional]: Markup properties as string dictionary (`""` creates no markup) (`Bluebeam Script Reference.pdf, p. 25`).
    * `pAddTextToComment` [Bool, Optional]: Place search term in comment field (`Bluebeam Script Reference.pdf, p. 25`).
    * `pPageRange` [String, Optional]: Page range (`-1` for all) (`Bluebeam Script Reference.pdf, p. 25`).
* **SetOpenPassword**:
  * **Description**: Sets the open password on the active document (`Bluebeam Script Reference.pdf, p. 25-26`).
  * **Parameters**: `pOpenPassword` [String], `pEncryptionLevel` [String, Optional]: `"RC4"`, `"AES128"`, or `"AES256"` (`Bluebeam Script Reference.pdf, p. 26`).
* **SetPDFSecurity**:
  * **Description**: Applies security permissions to the active document (`Bluebeam Script Reference.pdf, p. 26`).
  * **Parameters**:
    * `pPermissionPassword` [String]: Master permission password (`Bluebeam Script Reference.pdf, p. 26`).
    * `pFlags` [Number]: Bitmask sum of allowed permissions:
      * `Print = 1`
      * `PrintLowOnly = 2`
      * `FillForms = 4`
      * `EditMarkups = 8`
      * `EditDocument = 16`
      * `PageManipulation = 32`
      * `CopyContent = 64`
      * `Accessibility = 128`
      (`Bluebeam Script Reference.pdf, p. 26`)
    * `pOpenPassword` [String, Optional]: Password required to open the file (`Bluebeam Script Reference.pdf, p. 26`).
    * `pEncryptionLevel` [String, Optional]: `"RC4"`, `"AES128"`, or `"AES256"` (`Bluebeam Script Reference.pdf, p. 26`).
* **SplitPages**:
  * **Description**: Extracts all pages in the page range to individual PDF files (`Bluebeam Script Reference.pdf, p. 26-27`).
  * **Parameters**:
    * `pPageRange` [String]: Page range (`-1` for all) (`Bluebeam Script Reference.pdf, p. 26`).
    * `pDirectory` [String]: Output directory (`Bluebeam Script Reference.pdf, p. 26`).
    * `pUsePageLabels` [Bool, Optional]: Use page labels as file names (`Bluebeam Script Reference.pdf, p. 26`).
    * `pPageFormat` [String, Optional]: Numbering format suffix (e.g., `" Page 001"`) (`Bluebeam Script Reference.pdf, p. 26-27`).
* **Stamp**:
  * **Description**: Places a stamp on the active document (`Bluebeam Script Reference.pdf, p. 27`).
  * **Parameters**:
    * `pFileName` [String]: Stamp filename (`Bluebeam Script Reference.pdf, p. 27`).
    * `pOrigin` [String]: `"upperleft"`, `"upperright"`, `"lowerleft"`, `"lowerright"`, `"center"`, `"uppercenter"`, or `"lowercenter"` (`Bluebeam Script Reference.pdf, p. 27`).
    * `pXOffset` [Number]: X offset from origin in inches (`Bluebeam Script Reference.pdf, p. 27`).
    * `pYOffset` [Number]: Y offset from origin in inches (`Bluebeam Script Reference.pdf, p. 27`).
    * `pRotation` [Number, Optional]: Rotation in degrees (`Bluebeam Script Reference.pdf, p. 27`).
    * `pScale` [Number, Optional]: Scale factor (`0.5` = 50%) (`Bluebeam Script Reference.pdf, p. 27`).
    * `pOpacity` [Number, Optional]: Opacity (`0.4` = 40%) (`Bluebeam Script Reference.pdf, p. 27`).
    * `pBlendMode` [String, Optional]: `"normal"`, `"multiply"`, `"screen"`, `"overlay"`, `"darken"`, `"lighten"`, `"colordodge"`, `"colorburn"`, `"hardlight"`, `"softlight"`, `"difference"`, `"exclusion"`, `"luminosity"`, `"hue"`, `"saturation"`, or `"color"` (`Bluebeam Script Reference.pdf, p. 27`).
    * `pPageRange` [String, Optional]: Page range (`-1` for all) (`Bluebeam Script Reference.pdf, p. 27`).
    * `pLocked` [Bool, Optional]: Lock stamp (`Bluebeam Script Reference.pdf, p. 27`).
* **StateModelGet / StateModelList / StateModelsExport / StateModelsImport**:
  * `StateModelGet(pKey)`: Retrieves list of state keys for a state model (`Bluebeam Script Reference.pdf, p. 27-28`).
  * `StateModelList()`: Retrieves dictionary of State Model keys mapped to UI descriptions (`Bluebeam Script Reference.pdf, p. 28`).
  * `StateModelsExport(pFileName)`: Exports State Models definition to `.xml` (`Bluebeam Script Reference.pdf, p. 28`).
  * `StateModelsImport(pFileName)`: Imports State Model definition `.xml` overwriting existing state models (`Bluebeam Script Reference.pdf, p. 28`).
* **Thumbnail**:
  * **Description**: Creates page thumbnail image(s) (`.bmp`, `.png`, `.jpg`, etc.) (`Bluebeam Script Reference.pdf, p. 28-29`).
  * **Parameters**: `pWidth` [Number] (pixels), `pHeight` [Number] (pixels), `pFileName` [String], `pPageFormat` [String, Optional] (e.g., `" Page 001"`), `pPageRange` [String, Optional] (`-1` for all), `pShowPopups` [Bool, Optional] (`Bluebeam Script Reference.pdf, p. 29`).
* **Unflatten**:
  * **Description**: Reverses recoverable flattening on the active document (`Bluebeam Script Reference.pdf, p. 29`).
  * **Parameters**: `pPageRange` [String, Optional] (`-1` for all) (`Bluebeam Script Reference.pdf, p. 29`).
* **UnlockPDFA**:
  * **Description**: Unlocks the current PDF/A-1b document for editing (`Bluebeam Script Reference.pdf, p. 29`).
  * **Parameters**: None (`Bluebeam Script Reference.pdf, p. 29`).
* **UserNameGet / UserNameSet**:
  * `UserNameGet()`: Returns the user name used when adding or modifying markups (`Bluebeam Script Reference.pdf, p. 29`).
  * `UserNameSet(pUserName)`: Sets the user name used when adding or modifying markups (`Bluebeam Script Reference.pdf, p. 29-30`).
* **View**:
  * **Description**: Launches a file in the default viewing application (`Bluebeam Script Reference.pdf, p. 30`).
  * **Parameters**: `pFileName` [String, Optional] (`Bluebeam Script Reference.pdf, p. 30`).
