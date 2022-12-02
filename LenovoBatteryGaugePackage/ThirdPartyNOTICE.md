This Lenovo Plug-in may incorporate components from the projects listed
below. The original copyright notices and the licenses set forth below are for 
informational purposes only and were collected using common, reasonable means. 
Lenovo reserves all rights not expressly granted herein, whether by implication, 
estoppel or otherwise.

--------------------------------------------------------------------------------
DuiLib 1.2.23
--------------------------------------------------------------------------------

* Declared Licenses *
BSD-3-Clause License

Copyright (c) 2010-2011, duilib develop team<<beginOptional>>
All rights reserved.<<endOptional>>

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

   1. Redistributions of source code must retain the above copyright notice, this
      list of conditions and the following disclaimer.

   2. Redistributions in binary form must reproduce the above copyright notice,
      this list of conditions and the following disclaimer in the documentation

      and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


* Other Licenses *

/Utils/stb_image.c
****************** 
/* stbi-1.33 - public domain JPEG/PNG reader - http://nothings.org/stb_image.c


/Utils/XUnzip.cpp
****************** 
// This is version 2002-Feb-16 of the Info-ZIP copyright and license. The 
// definitive version of this document should be available at 
// ftp://ftp.info-zip.org/pub/infozip/license.html indefinitely.
// 
// Copyright (c) 1990-2002 Info-ZIP.  All rights reserved.
//
// For the purposes of this copyright and license, "Info-ZIP" is defined as
// the following set of individuals:
//
//   Mark Adler, John Bush, Karl Davis, Harald Denker, Jean-Michel Dubois,
//   Jean-loup Gailly, Hunter Goatley, Ian Gorman, Chris Herborth, Dirk Haase,
//   Greg Hartwig, Robert Heath, Jonathan Hudson, Paul Kienitz, 
//   David Kirschbaum, Johnny Lee, Onno van der Linden, Igor Mandrichenko, 
//   Steve P. Miller, Sergio Monesi, Keith Owens, George Petrov, Greg Roelofs, 
//   Kai Uwe Rommel, Steve Salisbury, Dave Smith, Christian Spieler, 
//   Antoine Verheijen, Paul von Behren, Rich Wales, Mike White
//
// This software is provided "as is", without warranty of any kind, express
// or implied.  In no event shall Info-ZIP or its contributors be held liable
// for any direct, indirect, incidental, special or consequential damages
// arising out of the use of or inability to use this software.
//
// Permission is granted to anyone to use this software for any purpose,
// including commercial applications, and to alter it and redistribute it
// freely, subject to the following restrictions:
//
//    1. Redistributions of source code must retain the above copyright notice,
//       definition, disclaimer, and this list of conditions.
//
//    2. Redistributions in binary form (compiled executables) must reproduce 
//       the above copyright notice, definition, disclaimer, and this list of 
//       conditions in documentation and/or other materials provided with the 
//       distribution. The sole exception to this condition is redistribution 
//       of a standard UnZipSFX binary as part of a self-extracting archive; 
//       that is permitted without inclusion of this license, as long as the 
//       normal UnZipSFX banner has not been removed from the binary or disabled.
//
//    3. Altered versions--including, but not limited to, ports to new 
//       operating systems, existing ports with new graphical interfaces, and 
//       dynamic, shared, or static library versions--must be plainly marked 
//       as such and must not be misrepresented as being the original source.  
//       Such altered versions also must not be misrepresented as being 
//       Info-ZIP releases--including, but not limited to, labeling of the 
//       altered versions with the names "Info-ZIP" (or any variation thereof, 
//       including, but not limited to, different capitalizations), 
//       "Pocket UnZip", "WiZ" or "MacZip" without the explicit permission of 
//       Info-ZIP.  Such altered versions are further prohibited from 
//       misrepresentative use of the Zip-Bugs or Info-ZIP e-mail addresses or 
//       of the Info-ZIP URL(s).
//
//    4. Info-ZIP retains the right to use the names "Info-ZIP", "Zip", "UnZip",
//       "UnZipSFX", "WiZ", "Pocket UnZip", "Pocket Zip", and "MacZip" for its 
//       own source and binary releases.


* Package Info *

Package Manager: https://github.com/duilib/duilib


--------------------------------------------------------------------------------
XUnzip.cpp 1.3
--------------------------------------------------------------------------------

* Declared Licenses *
Info-Zip License

 
// This is version 2002-Feb-16 of the Info-ZIP copyright and license. The 
// definitive version of this document should be available at 
// ftp://ftp.info-zip.org/pub/infozip/license.html indefinitely.
// 
// Copyright (c) 1990-2002 Info-ZIP.  All rights reserved.
//
// For the purposes of this copyright and license, "Info-ZIP" is defined as
// the following set of individuals:
//
//   Mark Adler, John Bush, Karl Davis, Harald Denker, Jean-Michel Dubois,
//   Jean-loup Gailly, Hunter Goatley, Ian Gorman, Chris Herborth, Dirk Haase,
//   Greg Hartwig, Robert Heath, Jonathan Hudson, Paul Kienitz, 
//   David Kirschbaum, Johnny Lee, Onno van der Linden, Igor Mandrichenko, 
//   Steve P. Miller, Sergio Monesi, Keith Owens, George Petrov, Greg Roelofs, 
//   Kai Uwe Rommel, Steve Salisbury, Dave Smith, Christian Spieler, 
//   Antoine Verheijen, Paul von Behren, Rich Wales, Mike White
//
// This software is provided "as is", without warranty of any kind, express
// or implied.  In no event shall Info-ZIP or its contributors be held liable
// for any direct, indirect, incidental, special or consequential damages
// arising out of the use of or inability to use this software.
//
// Permission is granted to anyone to use this software for any purpose,
// including commercial applications, and to alter it and redistribute it
// freely, subject to the following restrictions:
//
//    1. Redistributions of source code must retain the above copyright notice,
//       definition, disclaimer, and this list of conditions.
//
//    2. Redistributions in binary form (compiled executables) must reproduce 
//       the above copyright notice, definition, disclaimer, and this list of 
//       conditions in documentation and/or other materials provided with the 
//       distribution. The sole exception to this condition is redistribution 
//       of a standard UnZipSFX binary as part of a self-extracting archive; 
//       that is permitted without inclusion of this license, as long as the 
//       normal UnZipSFX banner has not been removed from the binary or disabled.
//
//    3. Altered versions--including, but not limited to, ports to new 
//       operating systems, existing ports with new graphical interfaces, and 
//       dynamic, shared, or static library versions--must be plainly marked 
//       as such and must not be misrepresented as being the original source.  
//       Such altered versions also must not be misrepresented as being 
//       Info-ZIP releases--including, but not limited to, labeling of the 
//       altered versions with the names "Info-ZIP" (or any variation thereof, 
//       including, but not limited to, different capitalizations), 
//       "Pocket UnZip", "WiZ" or "MacZip" without the explicit permission of 
//       Info-ZIP.  Such altered versions are further prohibited from 
//       misrepresentative use of the Zip-Bugs or Info-ZIP e-mail addresses or 
//       of the Info-ZIP URL(s).
//
//    4. Info-ZIP retains the right to use the names "Info-ZIP", "Zip", "UnZip",
//       "UnZipSFX", "WiZ", "Pocket UnZip", "Pocket Zip", and "MacZip" for its 
//       own source and binary releases.


* Package Info *

Package Manager: http://infozip.sourceforge.net/ 


--------------------------------------------------------------------------------
Microsoft.CSharp 4.0.1
Microsoft.NETCore.Platforms	1.0.2
Microsoft.NETCore.Targets	1.0.2
System.Collections.Immutable	1.2.0
System.ComponentModel.Annotations	4.1.0
System.Diagnostics.DiagnosticSource	4.0.0
System.Reflection.Context	4.0.1
System.Reflection.DispatchProxy	4.0.1
System.Reflection.Emit	4.0.1
System.Reflection.Emit.ILGeneration	4.0.1
System.Reflection.Emit.Lightweight	4.0.1
System.Reflection.Metadata	1.3.0
System.Reflection.TypeExtensions	4.1.0
System.Runtime.WindowsRuntime	4.0.11
System.Runtime.WindowsRuntime.UI.Xaml	4.0.1
System.Security.Cryptography.Cng	4.2.0
System.Text.Encoding.CodePages	4.0.1
System.Threading.Tasks.Dataflow	4.6.0
--------------------------------------------------------------------------------

* Declared Licenses *
MS-NET

MICROSOFT SOFTWARE LICENSE TERMS


MICROSOFT .NET LIBRARY 

These license terms are an agreement between Microsoft Corporation (or based on where you live, one of its affiliates) and you. Please read them. They apply to the software named above, which includes the media on which you received it, if any. The terms also apply to any Microsoft

·         updates,

·         supplements,

·         Internet-based services, and

·         support services

for this software, unless other terms accompany those items. If so, those terms apply.

BY USING THE SOFTWARE, YOU ACCEPT THESE TERMS. IF YOU DO NOT ACCEPT THEM, DO NOT USE THE SOFTWARE.


IF YOU COMPLY WITH THESE LICENSE TERMS, YOU HAVE THE PERPETUAL RIGHTS BELOW.

1.    INSTALLATION AND USE RIGHTS. 

a.    Installation and Use. You may install and use any number of copies of the software to design, develop and test your programs.

b.    Third Party Programs. The software may include third party programs that Microsoft, not the third party, licenses to you under this agreement. Notices, if any, for the third party program are included for your information only.

2.    ADDITIONAL LICENSING REQUIREMENTS AND/OR USE RIGHTS.

a.    DISTRIBUTABLE CODE.  The software is comprised of Distributable Code. “Distributable Code” is code that you are permitted to distribute in programs you develop if you comply with the terms below.

i.      Right to Use and Distribute. 

·         You may copy and distribute the object code form of the software.

·         Third Party Distribution. You may permit distributors of your programs to copy and distribute the Distributable Code as part of those programs.

ii.    Distribution Requirements. For any Distributable Code you distribute, you must

·         add significant primary functionality to it in your programs;

·         require distributors and external end users to agree to terms that protect it at least as much as this agreement;

·         display your valid copyright notice on your programs; and

·         indemnify, defend, and hold harmless Microsoft from any claims, including attorneys’ fees, related to the distribution or use of your programs.

iii.   Distribution Restrictions. You may not

·         alter any copyright, trademark or patent notice in the Distributable Code;

·         use Microsoft’s trademarks in your programs’ names or in a way that suggests your programs come from or are endorsed by Microsoft;

·         include Distributable Code in malicious, deceptive or unlawful programs; or

·         modify or distribute the source code of any Distributable Code so that any part of it becomes subject to an Excluded License. An Excluded License is one that requires, as a condition of use, modification or distribution, that

·         the code be disclosed or distributed in source code form; or

·         others have the right to modify it.

3.    SCOPE OF LICENSE. The software is licensed, not sold. This agreement only gives you some rights to use the software. Microsoft reserves all other rights. Unless applicable law gives you more rights despite this limitation, you may use the software only as expressly permitted in this agreement. In doing so, you must comply with any technical limitations in the software that only allow you to use it in certain ways. You may not

·         work around any technical limitations in the software;

·         reverse engineer, decompile or disassemble the software, except and only to the extent that applicable law expressly permits, despite this limitation;

·         publish the software for others to copy;

·         rent, lease or lend the software;

·         transfer the software or this agreement to any third party; or

·         use the software for commercial software hosting services.

4.    BACKUP COPY. You may make one backup copy of the software. You may use it only to reinstall the software.

5.    DOCUMENTATION. Any person that has valid access to your computer or internal network may copy and use the documentation for your internal, reference purposes.

6.    EXPORT RESTRICTIONS. The software is subject to United States export laws and regulations. You must comply with all domestic and international export laws and regulations that apply to the software. These laws include restrictions on destinations, end users and end use. For additional information, see www.microsoft.com/exporting.

7.    SUPPORT SERVICES. Because this software is “as is,” we may not provide support services for it.

8.    ENTIRE AGREEMENT. This agreement, and the terms for supplements, updates, Internet-based services and support services that you use, are the entire agreement for the software and support services.

9.    APPLICABLE LAW.

a.    United States. If you acquired the software in the United States, Washington state law governs the interpretation of this agreement and applies to claims for breach of it, regardless of conflict of laws principles. The laws of the state where you live govern all other claims, including claims under state consumer protection laws, unfair competition laws, and in tort.

b.    Outside the United States. If you acquired the software in any other country, the laws of that country apply.

10.  LEGAL EFFECT. This agreement describes certain legal rights. You may have other rights under the laws of your country. You may also have rights with respect to the party from whom you acquired the software. This agreement does not change your rights under the laws of your country if the laws of your country do not permit it to do so.

11.  DISCLAIMER OF WARRANTY. THE SOFTWARE IS LICENSED “AS-IS.” YOU BEAR THE RISK OF USING IT. MICROSOFT GIVES NO EXPRESS WARRANTIES, GUARANTEES OR CONDITIONS. YOU MAY HAVE ADDITIONAL CONSUMER RIGHTS OR STATUTORY GUARANTEES UNDER YOUR LOCAL LAWS WHICH THIS AGREEMENT CANNOT CHANGE. TO THE EXTENT PERMITTED UNDER YOUR LOCAL LAWS, MICROSOFT EXCLUDES THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT.

FOR AUSTRALIA – YOU HAVE STATUTORY GUARANTEES UNDER THE AUSTRALIAN CONSUMER LAW AND NOTHING IN THESE TERMS IS INTENDED TO AFFECT THOSE RIGHTS.

12.  LIMITATION ON AND EXCLUSION OF REMEDIES AND DAMAGES. YOU CAN RECOVER FROM MICROSOFT AND ITS SUPPLIERS ONLY DIRECT DAMAGES UP TO U.S. $5.00. YOU CANNOT RECOVER ANY OTHER DAMAGES, INCLUDING CONSEQUENTIAL, LOST PROFITS, SPECIAL, INDIRECT OR INCIDENTAL DAMAGES.

This limitation applies to

·         anything related to the software, services, content (including code) on third party Internet sites, or third party programs; and

·         claims for breach of contract, breach of warranty, guarantee or condition, strict liability, negligence, or other tort to the extent permitted by applicable law.

It also applies even if Microsoft knew or should have known about the possibility of the damages. The above limitation or exclusion may not apply to you because your country may not allow the exclusion or limitation of incidental, consequential or other damages.

Please note: As this software is distributed in Quebec, Canada, some of the clauses in this agreement are provided below in French.

Remarque : Ce logiciel étant distribué au Québec, Canada, certaines des clauses dans ce contrat sont fournies ci-dessous en français.

EXONÉRATION DE GARANTIE. Le logiciel visé par une licence est offert « tel quel ». Toute utilisation de ce logiciel est à votre seule risque et péril. Microsoft n’accorde aucune autre garantie expresse. Vous pouvez bénéficier de droits additionnels en vertu du droit local sur la protection des consommateurs, que ce contrat ne peut modifier. La ou elles sont permises par le droit locale, les garanties implicites de qualité marchande, d’adéquation à un usage particulier et d’absence de contrefaçon sont exclues.

LIMITATION DES DOMMAGES-INTÉRÊTS ET EXCLUSION DE RESPONSABILITÉ POUR LES DOMMAGES. Vous pouvez obtenir de Microsoft et de ses fournisseurs une indemnisation en cas de dommages directs uniquement à hauteur de 5,00 $ US. Vous ne pouvez prétendre à aucune indemnisation pour les autres dommages, y compris les dommages spéciaux, indirects ou accessoires et pertes de bénéfices.

Cette limitation concerne :

·         tout ce qui est relié au logiciel, aux services ou au contenu (y compris le code) figurant sur des sites Internet tiers ou dans des programmes tiers ; et

·         les réclamations au titre de violation de contrat ou de garantie, ou au titre de responsabilité stricte, de négligence ou d’une autre faute dans la limite autorisée par la loi en vigueur.

Elle s’applique également, même si Microsoft connaissait ou devrait connaître l’éventualité d’un tel dommage. Si votre pays n’autorise pas l’exclusion ou la limitation de responsabilité pour les dommages indirects, accessoires ou de quelque nature que ce soit, il se peut que la limitation ou l’exclusion ci-dessus ne s’appliquera pas à votre égard.

EFFET JURIDIQUE. Le présent contrat décrit certains droits juridiques. Vous pourriez avoir d’autres droits prévus par les lois de votre pays. Le présent contrat ne modifie pas les droits que vous confèrent les lois de votre pays si celles-ci ne le permettent pas.

 
* Other Licenses *

This Microsoft .NET Library may incorporate components from the projects listed
below. Microsoft licenses these components under the Microsoft .NET Library
software license terms. The original copyright notices and the licenses under
which Microsoft received such components are set forth below for informational
purposes only. Microsoft reserves all rights not expressly granted herein,
whether by implication, estoppel or otherwise.

1.	.NET Core (https://github.com/dotnet/core/)

.NET Core
Copyright (c) .NET Foundation and Contributors

The MIT License (MIT)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.


* Package Info *

Authors: Microsoft

Package Manager: Nuget

Project URL: https://github.com/dotnet/corefx


--------------------------------------------------------------------------------
Newtonsoft.Json (12.0.3)
--------------------------------------------------------------------------------

* Declared Licenses *
MIT

The MIT License (MIT)

Copyright (c) 2007 James Newton-King

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.



* Package Info *

Authors: James Newton-King

Package Manager: Nuget

Project URL: https://www.newtonsoft.com/json


--------------------------------------------------------------------------------
Microsoft.Windows.CppWinRT (2.0.200316.3)
--------------------------------------------------------------------------------

* Declared Licenses *
MIT

MIT License

Copyright (c) Microsoft Corporation.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE


* Package Info *

Authors: Microsoft

Package Manager: Nuget

Project URL: https://github.com/Microsoft/xlang/tree/master/src/package/cppwinrt/nuget

--------------------------------------------------------------------------------
Microsoft.NETCore	5.0.2
Microsoft.NETCore.Jit	1.0.3
Microsoft.NETCore.Portable.Compatibility	1.0.2
Microsoft.NETCore.Runtime.CoreCLR	1.0.3
Microsoft.NETCore.Windows.ApiSets	1.0.1
Microsoft.VisualBasic	10.0.1
Microsoft.Win32.Primitives	4.0.1
runtime.aot.System.Collections	4.0.10
runtime.aot.System.Diagnostics.Tools	4.0.1
runtime.aot.System.Diagnostics.Tracing	4.0.20
runtime.aot.System.Globalization	4.0.11
runtime.aot.System.Globalization.Calendars	4.0.1
runtime.aot.System.IO	4.1.0
runtime.aot.System.Reflection	4.0.10
runtime.aot.System.Reflection.Extensions	4.0.0
runtime.aot.System.Reflection.Primitives	4.0.0
runtime.aot.System.Resources.ResourceManager	4.0.0
runtime.aot.System.Runtime	4.0.20
runtime.aot.System.Runtime.Handles	4.0.1
runtime.aot.System.Runtime.InteropServices	4.0.20
runtime.aot.System.Text.Encoding	4.0.11
runtime.aot.System.Text.Encoding.Extensions	4.0.11
runtime.aot.System.Threading.Tasks	4.0.11
runtime.aot.System.Threading.Timer	4.0.1
runtime.native.System.IO.Compression	4.1.0
runtime.native.System.Security.Cryptography	4.0.0
runtime.win.Microsoft.Win32.Primitives	4.0.1
runtime.win.System.Diagnostics.Debug	4.0.11
runtime.win.System.IO.FileSystem	4.0.1
runtime.win.System.Net.Primitives	4.0.11
runtime.win.System.Net.Sockets	4.1.0
runtime.win.System.Runtime.Extensions	4.1.0
runtime.win10-arm-aot.runtime.native.System.IO.Compression	4.0.1
runtime.win7.System.Private.Uri	4.0.4
runtime.win8-arm.Microsoft.NETCore.Runtime.CoreCLR	1.0.2
System.AppContext	4.1.0
System.Buffers	4.0.0
System.Collections	4.0.11
System.Collections.Concurrent	4.0.12
System.Collections.NonGeneric	4.0.1
System.Collections.Specialized	4.0.1
System.ComponentModel	4.0.1
System.ComponentModel.EventBasedAsync	4.0.11
System.Data.Common	4.1.0
System.Diagnostics.Contracts	4.0.1
System.Diagnostics.Debug	4.0.11
System.Diagnostics.StackTrace	4.0.2
System.Diagnostics.Tools	4.0.1
System.Diagnostics.Tracing	4.1.0
System.Dynamic.Runtime	4.0.11
System.Globalization	4.0.11
System.Globalization.Calendars	4.0.1
System.Globalization.Extensions	4.0.1
System.IO	4.1.0
System.IO.Compression	4.1.1
System.IO.Compression.ZipFile	4.0.1
System.IO.FileSystem	4.0.1
System.IO.FileSystem.Primitives	4.0.1
System.IO.IsolatedStorage	4.0.1
System.IO.UnmanagedMemoryStream	4.0.1
System.Linq	4.1.0
System.Linq.Expressions	4.1.0
System.Linq.Parallel	4.0.1
System.Linq.Queryable	4.0.1
System.Net.Http	4.1.0
System.Net.Http.Rtc	4.0.1
System.Net.NameResolution	4.0.0
System.Net.NetworkInformation	4.1.0
System.Net.Primitives	4.0.11
System.Net.Requests	4.0.11
System.Net.Sockets	4.1.0
System.Net.WebHeaderCollection	4.0.1
System.Net.WebSockets	4.0.0
System.Net.WebSockets.Client	4.0.2
System.Numerics.Vectors	4.1.1
System.Numerics.Vectors.WindowsRuntime	4.0.1
System.ObjectModel	4.0.12
System.Private.DataContractSerialization	4.1.2
System.Private.Uri	4.0.1
System.Reflection	4.1.0
System.Reflection.Extensions	4.0.1
System.Reflection.Primitives	4.0.1
System.Resources.ResourceManager	4.0.1
System.Runtime	4.1.0
System.Runtime.Extensions	4.1.0
System.Runtime.Handles	4.0.1
System.Runtime.InteropServices	4.1.0
System.Runtime.InteropServices.WindowsRuntime	4.0.1
System.Runtime.Numerics	4.0.1
System.Runtime.Serialization.Json	4.0.3
System.Runtime.Serialization.Primitives	4.1.1
System.Runtime.Serialization.Xml	4.1.2
System.Security.Claims	4.0.1
System.Security.Cryptography.Algorithms	4.2.0
System.Security.Cryptography.Encoding	4.0.0
System.Security.Cryptography.Primitives	4.0.0
System.Security.Cryptography.X509Certificates	4.1.0
System.Security.Principal	4.0.1
System.Text.Encoding	4.0.11
System.Text.Encoding.Extensions	4.0.11
System.Text.RegularExpressions	4.1.0
System.Threading	4.0.11
System.Threading.Overlapped	4.0.1
System.Threading.Tasks	4.0.11
System.Threading.Tasks.Extensions	4.0.0
System.Threading.Tasks.Parallel	4.0.1
System.Threading.Timer	4.0.1
System.Xml.ReaderWriter	4.0.11
System.Xml.XDocument	4.0.11
System.Xml.XmlDocument	4.0.1
System.Xml.XmlSerializer	4.0.11
--------------------------------------------------------------------------------

* Declared Licenses *
MS-NET

MICROSOFT SOFTWARE LICENSE TERMS


MICROSOFT .NET LIBRARY 

These license terms are an agreement between Microsoft Corporation (or based on where you live, one of its affiliates) and you. Please read them. They apply to the software named above, which includes the media on which you received it, if any. The terms also apply to any Microsoft

·         updates,

·         supplements,

·         Internet-based services, and

·         support services

for this software, unless other terms accompany those items. If so, those terms apply.

BY USING THE SOFTWARE, YOU ACCEPT THESE TERMS. IF YOU DO NOT ACCEPT THEM, DO NOT USE THE SOFTWARE.


IF YOU COMPLY WITH THESE LICENSE TERMS, YOU HAVE THE PERPETUAL RIGHTS BELOW.

1.    INSTALLATION AND USE RIGHTS. 

a.    Installation and Use. You may install and use any number of copies of the software to design, develop and test your programs.

b.    Third Party Programs. The software may include third party programs that Microsoft, not the third party, licenses to you under this agreement. Notices, if any, for the third party program are included for your information only.

2.    ADDITIONAL LICENSING REQUIREMENTS AND/OR USE RIGHTS.

a.    DISTRIBUTABLE CODE.  The software is comprised of Distributable Code. “Distributable Code” is code that you are permitted to distribute in programs you develop if you comply with the terms below.

i.      Right to Use and Distribute. 

·         You may copy and distribute the object code form of the software.

·         Third Party Distribution. You may permit distributors of your programs to copy and distribute the Distributable Code as part of those programs.

ii.    Distribution Requirements. For any Distributable Code you distribute, you must

·         add significant primary functionality to it in your programs;

·         require distributors and external end users to agree to terms that protect it at least as much as this agreement;

·         display your valid copyright notice on your programs; and

·         indemnify, defend, and hold harmless Microsoft from any claims, including attorneys’ fees, related to the distribution or use of your programs.

iii.   Distribution Restrictions. You may not

·         alter any copyright, trademark or patent notice in the Distributable Code;

·         use Microsoft’s trademarks in your programs’ names or in a way that suggests your programs come from or are endorsed by Microsoft;

·         include Distributable Code in malicious, deceptive or unlawful programs; or

·         modify or distribute the source code of any Distributable Code so that any part of it becomes subject to an Excluded License. An Excluded License is one that requires, as a condition of use, modification or distribution, that

·         the code be disclosed or distributed in source code form; or

·         others have the right to modify it.

3.    SCOPE OF LICENSE. The software is licensed, not sold. This agreement only gives you some rights to use the software. Microsoft reserves all other rights. Unless applicable law gives you more rights despite this limitation, you may use the software only as expressly permitted in this agreement. In doing so, you must comply with any technical limitations in the software that only allow you to use it in certain ways. You may not

·         work around any technical limitations in the software;

·         reverse engineer, decompile or disassemble the software, except and only to the extent that applicable law expressly permits, despite this limitation;

·         publish the software for others to copy;

·         rent, lease or lend the software;

·         transfer the software or this agreement to any third party; or

·         use the software for commercial software hosting services.

4.    BACKUP COPY. You may make one backup copy of the software. You may use it only to reinstall the software.

5.    DOCUMENTATION. Any person that has valid access to your computer or internal network may copy and use the documentation for your internal, reference purposes.

6.    EXPORT RESTRICTIONS. The software is subject to United States export laws and regulations. You must comply with all domestic and international export laws and regulations that apply to the software. These laws include restrictions on destinations, end users and end use. For additional information, see www.microsoft.com/exporting.

7.    SUPPORT SERVICES. Because this software is “as is,” we may not provide support services for it.

8.    ENTIRE AGREEMENT. This agreement, and the terms for supplements, updates, Internet-based services and support services that you use, are the entire agreement for the software and support services.

9.    APPLICABLE LAW.

a.    United States. If you acquired the software in the United States, Washington state law governs the interpretation of this agreement and applies to claims for breach of it, regardless of conflict of laws principles. The laws of the state where you live govern all other claims, including claims under state consumer protection laws, unfair competition laws, and in tort.

b.    Outside the United States. If you acquired the software in any other country, the laws of that country apply.

10.  LEGAL EFFECT. This agreement describes certain legal rights. You may have other rights under the laws of your country. You may also have rights with respect to the party from whom you acquired the software. This agreement does not change your rights under the laws of your country if the laws of your country do not permit it to do so.

11.  DISCLAIMER OF WARRANTY. THE SOFTWARE IS LICENSED “AS-IS.” YOU BEAR THE RISK OF USING IT. MICROSOFT GIVES NO EXPRESS WARRANTIES, GUARANTEES OR CONDITIONS. YOU MAY HAVE ADDITIONAL CONSUMER RIGHTS OR STATUTORY GUARANTEES UNDER YOUR LOCAL LAWS WHICH THIS AGREEMENT CANNOT CHANGE. TO THE EXTENT PERMITTED UNDER YOUR LOCAL LAWS, MICROSOFT EXCLUDES THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT.

FOR AUSTRALIA – YOU HAVE STATUTORY GUARANTEES UNDER THE AUSTRALIAN CONSUMER LAW AND NOTHING IN THESE TERMS IS INTENDED TO AFFECT THOSE RIGHTS.

12.  LIMITATION ON AND EXCLUSION OF REMEDIES AND DAMAGES. YOU CAN RECOVER FROM MICROSOFT AND ITS SUPPLIERS ONLY DIRECT DAMAGES UP TO U.S. $5.00. YOU CANNOT RECOVER ANY OTHER DAMAGES, INCLUDING CONSEQUENTIAL, LOST PROFITS, SPECIAL, INDIRECT OR INCIDENTAL DAMAGES.

This limitation applies to

·         anything related to the software, services, content (including code) on third party Internet sites, or third party programs; and

·         claims for breach of contract, breach of warranty, guarantee or condition, strict liability, negligence, or other tort to the extent permitted by applicable law.

It also applies even if Microsoft knew or should have known about the possibility of the damages. The above limitation or exclusion may not apply to you because your country may not allow the exclusion or limitation of incidental, consequential or other damages.

Please note: As this software is distributed in Quebec, Canada, some of the clauses in this agreement are provided below in French.

Remarque : Ce logiciel étant distribué au Québec, Canada, certaines des clauses dans ce contrat sont fournies ci-dessous en français.

EXONÉRATION DE GARANTIE. Le logiciel visé par une licence est offert « tel quel ». Toute utilisation de ce logiciel est à votre seule risque et péril. Microsoft n’accorde aucune autre garantie expresse. Vous pouvez bénéficier de droits additionnels en vertu du droit local sur la protection des consommateurs, que ce contrat ne peut modifier. La ou elles sont permises par le droit locale, les garanties implicites de qualité marchande, d’adéquation à un usage particulier et d’absence de contrefaçon sont exclues.

LIMITATION DES DOMMAGES-INTÉRÊTS ET EXCLUSION DE RESPONSABILITÉ POUR LES DOMMAGES. Vous pouvez obtenir de Microsoft et de ses fournisseurs une indemnisation en cas de dommages directs uniquement à hauteur de 5,00 $ US. Vous ne pouvez prétendre à aucune indemnisation pour les autres dommages, y compris les dommages spéciaux, indirects ou accessoires et pertes de bénéfices.

Cette limitation concerne :

·         tout ce qui est relié au logiciel, aux services ou au contenu (y compris le code) figurant sur des sites Internet tiers ou dans des programmes tiers ; et

·         les réclamations au titre de violation de contrat ou de garantie, ou au titre de responsabilité stricte, de négligence ou d’une autre faute dans la limite autorisée par la loi en vigueur.

Elle s’applique également, même si Microsoft connaissait ou devrait connaître l’éventualité d’un tel dommage. Si votre pays n’autorise pas l’exclusion ou la limitation de responsabilité pour les dommages indirects, accessoires ou de quelque nature que ce soit, il se peut que la limitation ou l’exclusion ci-dessus ne s’appliquera pas à votre égard.

EFFET JURIDIQUE. Le présent contrat décrit certains droits juridiques. Vous pourriez avoir d’autres droits prévus par les lois de votre pays. Le présent contrat ne modifie pas les droits que vous confèrent les lois de votre pays si celles-ci ne le permettent pas.

 
* Other Licenses *

This Microsoft .NET Library may incorporate components from the projects listed
below. Microsoft licenses these components under the Microsoft .NET Library
software license terms. The original copyright notices and the licenses under
which Microsoft received such components are set forth below for informational
purposes only. Microsoft reserves all rights not expressly granted herein,
whether by implication, estoppel or otherwise.

1.	.NET Core (https://github.com/dotnet/core/)

.NET Core
Copyright (c) .NET Foundation and Contributors

The MIT License (MIT)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.


* Package Info *

Authors: Microsoft

Package Manager: Nuget

Project URL: https://dot.net/


--------------------------------------------------------------------------------
pugixml (1.11.0)
--------------------------------------------------------------------------------

* Declared Licenses *
MIT

Copyright (c) 2006-2018 Arseny Kapoulkine

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.


* Package Info *

Authors: Arseny Kapoulkine

Package Manager: Nuget

Project URL: https://pugixml.org/


--------------------------------------------------------------------------------
StyleCop.Analyzers (1.1.118)
--------------------------------------------------------------------------------

* Declared Licenses *
Multi-license: Apache-2.0 OR MIT

﻿Copyright (c) Tunnel Vision Laboratories, LLC. All rights reserved.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use
these files except in compliance with the License. You may obtain a copy of the
License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed
under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied. See the License for the
specific language governing permissions and limitations under the License.


* Other Licenses *

This project uses other open source projects, which are used under the terms
of the following license(s).

.NET Compiler Platform ("Roslyn")

  Copyright Microsoft.

  Licensed under the Apache License, Version 2.0 (the "License"); you may not use
  these files except in compliance with the License. You may obtain a copy of the
  License at

  http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software distributed
  under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
  CONDITIONS OF ANY KIND, either express or implied. See the License for the
  specific language governing permissions and limitations under the License.

Code Cracker

  Copyright 2014 Giovanni Bassi and Elemar Jr.

  Licensed under the Apache License, Version 2.0 (the "License"); you may not use
  these files except in compliance with the License. You may obtain a copy of the
  License at

  http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software distributed
  under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
  CONDITIONS OF ANY KIND, either express or implied. See the License for the
  specific language governing permissions and limitations under the License.

LightJson

  Copyright (c) 2017 Marcos López C.
  
  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:
  
  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.
  
  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
  THE SOFTWARE.


StyleCop Analyzers uses third-party libraries or other resources that may be
distributed under licenses different than the StyleCop Analyzers software.

In the event that we accidentally failed to list a required notice, please
bring it to our attention by posting an issue.

The attached notices are provided for information only.

License notice for StyleCop.Analyzers.Status
--------------------------------------------------

The MIT License (MIT)

Copyright (c) 2015 Dennis Fischer

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.


* Package Info *

Authors: Sam Harwell et. al.

Package Manager: Nuget

Project URL: https://github.com/DotNetAnalyzers/StyleCopAnalyzers


--------------------------------------------------------------------------------
System.IdentityModel.Tokens.Jwt 4.0.4.403061554
System.IdentityModel.Tokens.Jwt	6.7.1
Microsoft.IdentityModel.JsonWebTokens	6.7.1
Microsoft.IdentityModel.Logging	6.7.1
Microsoft.IdentityModel.Tokens	6.7.1
--------------------------------------------------------------------------------

* Declared Licenses *
MIT

Copyright (c) 2021, System.IdentityModel.Tokens.Jwt Contributors
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.


* Package Info *

Authors: Microsoft

Package Manager: Nuget

Project URL: https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet


--------------------------------------------------------------------------------
System.Private.ServiceModel	4.1.3
System.ServiceModel.Duplex	4.0.4
System.ServiceModel.Http	4.1.3
System.ServiceModel.NetTcp	4.1.3
System.ServiceModel.Primitives	4.1.3
System.ServiceModel.Security	4.0.4
--------------------------------------------------------------------------------

* Declared Licenses *
MS-NET

MICROSOFT SOFTWARE LICENSE TERMS


MICROSOFT .NET LIBRARY 

These license terms are an agreement between Microsoft Corporation (or based on where you live, one of its affiliates) and you. Please read them. They apply to the software named above, which includes the media on which you received it, if any. The terms also apply to any Microsoft

-         updates,

-         supplements,

-         Internet-based services, and

-         support services

for this software, unless other terms accompany those items. If so, those terms apply.

BY USING THE SOFTWARE, YOU ACCEPT THESE TERMS. IF YOU DO NOT ACCEPT THEM, DO NOT USE THE SOFTWARE.


IF YOU COMPLY WITH THESE LICENSE TERMS, YOU HAVE THE PERPETUAL RIGHTS BELOW.

1.    INSTALLATION AND USE RIGHTS. 

a.    Installation and Use. You may install and use any number of copies of the software to design, develop and test your programs.

b.    Third Party Programs. The software may include third party programs that Microsoft, not the third party, licenses to you under this agreement. Notices, if any, for the third party program are included for your information only.

2.    ADDITIONAL LICENSING REQUIREMENTS AND/OR USE RIGHTS.

a.    DISTRIBUTABLE CODE.  The software is comprised of Distributable Code. "Distributable Code" is code that you are permitted to distribute in programs you develop if you comply with the terms below.

i.      Right to Use and Distribute. 

-         You may copy and distribute the object code form of the software.

-         Third Party Distribution. You may permit distributors of your programs to copy and distribute the Distributable Code as part of those programs.

ii.    Distribution Requirements. For any Distributable Code you distribute, you must

-         add significant primary functionality to it in your programs;

-         require distributors and external end users to agree to terms that protect it at least as much as this agreement;

-         display your valid copyright notice on your programs; and

-         indemnify, defend, and hold harmless Microsoft from any claims, including attorneys' fees, related to the distribution or use of your programs.

iii.   Distribution Restrictions. You may not

-         alter any copyright, trademark or patent notice in the Distributable Code;

-         use Microsoft's trademarks in your programs' names or in a way that suggests your programs come from or are endorsed by Microsoft;

-         include Distributable Code in malicious, deceptive or unlawful programs; or

-         modify or distribute the source code of any Distributable Code so that any part of it becomes subject to an Excluded License. An Excluded License is one that requires, as a condition of use, modification or distribution, that

-         the code be disclosed or distributed in source code form; or

-         others have the right to modify it.

3.    SCOPE OF LICENSE. The software is licensed, not sold. This agreement only gives you some rights to use the software. Microsoft reserves all other rights. Unless applicable law gives you more rights despite this limitation, you may use the software only as expressly permitted in this agreement. In doing so, you must comply with any technical limitations in the software that only allow you to use it in certain ways. You may not

-         work around any technical limitations in the software;

-         reverse engineer, decompile or disassemble the software, except and only to the extent that applicable law expressly permits, despite this limitation;

-         publish the software for others to copy;

-         rent, lease or lend the software;

-         transfer the software or this agreement to any third party; or

-         use the software for commercial software hosting services.

4.    BACKUP COPY. You may make one backup copy of the software. You may use it only to reinstall the software.

5.    DOCUMENTATION. Any person that has valid access to your computer or internal network may copy and use the documentation for your internal, reference purposes.

6.    EXPORT RESTRICTIONS. The software is subject to United States export laws and regulations. You must comply with all domestic and international export laws and regulations that apply to the software. These laws include restrictions on destinations, end users and end use. For additional information, see www.microsoft.com/exporting.

7.    SUPPORT SERVICES. Because this software is "as is," we may not provide support services for it.

8.    ENTIRE AGREEMENT. This agreement, and the terms for supplements, updates, Internet-based services and support services that you use, are the entire agreement for the software and support services.

9.    APPLICABLE LAW.

a.    United States. If you acquired the software in the United States, Washington state law governs the interpretation of this agreement and applies to claims for breach of it, regardless of conflict of laws principles. The laws of the state where you live govern all other claims, including claims under state consumer protection laws, unfair competition laws, and in tort.

b.    Outside the United States. If you acquired the software in any other country, the laws of that country apply.

10.  LEGAL EFFECT. This agreement describes certain legal rights. You may have other rights under the laws of your country. You may also have rights with respect to the party from whom you acquired the software. This agreement does not change your rights under the laws of your country if the laws of your country do not permit it to do so.

11.  DISCLAIMER OF WARRANTY. THE SOFTWARE IS LICENSED "AS-IS." YOU BEAR THE RISK OF USING IT. MICROSOFT GIVES NO EXPRESS WARRANTIES, GUARANTEES OR CONDITIONS. YOU MAY HAVE ADDITIONAL CONSUMER RIGHTS OR STATUTORY GUARANTEES UNDER YOUR LOCAL LAWS WHICH THIS AGREEMENT CANNOT CHANGE. TO THE EXTENT PERMITTED UNDER YOUR LOCAL LAWS, MICROSOFT EXCLUDES THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT.

FOR AUSTRALIA - YOU HAVE STATUTORY GUARANTEES UNDER THE AUSTRALIAN CONSUMER LAW AND NOTHING IN THESE TERMS IS INTENDED TO AFFECT THOSE RIGHTS.

12.  LIMITATION ON AND EXCLUSION OF REMEDIES AND DAMAGES. YOU CAN RECOVER FROM MICROSOFT AND ITS SUPPLIERS ONLY DIRECT DAMAGES UP TO U.S. $5.00. YOU CANNOT RECOVER ANY OTHER DAMAGES, INCLUDING CONSEQUENTIAL, LOST PROFITS, SPECIAL, INDIRECT OR INCIDENTAL DAMAGES.

This limitation applies to

-         anything related to the software, services, content (including code) on third party Internet sites, or third party programs; and

-         claims for breach of contract, breach of warranty, guarantee or condition, strict liability, negligence, or other tort to the extent permitted by applicable law.

It also applies even if Microsoft knew or should have known about the possibility of the damages. The above limitation or exclusion may not apply to you because your country may not allow the exclusion or limitation of incidental, consequential or other damages.

Please note: As this software is distributed in Quebec, Canada, some of the clauses in this agreement are provided below in French.

Remarque : Ce logiciel etant distribue au Quebec, Canada, certaines des clauses dans ce contrat sont fournies ci-dessous en francais.

EXONERATION DE GARANTIE. Le logiciel vise par une licence est offert << tel quel >>. Toute utilisation de ce logiciel est a votre seule risque et peril. Microsoft n'accorde aucune autre garantie expresse. Vous pouvez beneficier de droits additionnels en vertu du droit local sur la protection des consommateurs, que ce contrat ne peut modifier. La ou elles sont permises par le droit locale, les garanties implicites de qualite marchande, d'adequation a un usage particulier et d'absence de contrefacon sont exclues.

LIMITATION DES DOMMAGES-INTERETS ET EXCLUSION DE RESPONSABILITE POUR LES DOMMAGES. Vous pouvez obtenir de Microsoft et de ses fournisseurs une indemnisation en cas de dommages directs uniquement a hauteur de 5,00 $ US. Vous ne pouvez pretendre a aucune indemnisation pour les autres dommages, y compris les dommages speciaux, indirects ou accessoires et pertes de benefices.

Cette limitation concerne :

-         tout ce qui est relie au logiciel, aux services ou au contenu (y compris le code) figurant sur des sites Internet tiers ou dans des programmes tiers ; et

-         les reclamations au titre de violation de contrat ou de garantie, ou au titre de responsabilite stricte, de negligence ou d'une autre faute dans la limite autorisee par la loi en vigueur.

Elle s'applique egalement, meme si Microsoft connaissait ou devrait connaitre l'eventualite d'un tel dommage. Si votre pays n'autorise pas l'exclusion ou la limitation de responsabilite pour les dommages indirects, accessoires ou de quelque nature que ce soit, il se peut que la limitation ou l'exclusion ci-dessus ne s'appliquera pas a votre egard.

EFFET JURIDIQUE. Le present contrat decrit certains droits juridiques. Vous pourriez avoir d'autres droits prevus par les lois de votre pays. Le present contrat ne modifie pas les droits que vous conferent les lois de votre pays si celles-ci ne le permettent pas.

 
* Other Licenses *

This Microsoft .NET Library may incorporate components from the projects listed
below. Microsoft licenses these components under the Microsoft .NET Library
software license terms. The original copyright notices and the licenses under
which Microsoft received such components are set forth below for informational
purposes only. Microsoft reserves all rights not expressly granted herein,
whether by implication, estoppel or otherwise.

1.	.NET Core (https://github.com/dotnet/core/)

.NET Core
Copyright (c) .NET Foundation and Contributors

The MIT License (MIT)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.


* Package Info *

Authors: Microsoft

Package Manager: Nuget

Project URL: https://github.com/dotnet/wcf


--------------------------------------------------------------------------------
tinyxml 2.6.1
--------------------------------------------------------------------------------

* Declared Licenses *
Zlib

TinyXML is released under the zlib license:

This software is provided 'as-is', without any express or implied 
warranty. In no event will the authors be held liable for any 
damages arising from the use of this software.

Permission is granted to anyone to use this software for any 
purpose, including commercial applications, and to alter it and 
redistribute it freely, subject to the following restrictions:

1. The origin of this software must not be misrepresented; you must 
not claim that you wrote the original software. If you use this 
software in a product, an acknowledgment in the product documentation 
would be appreciated but is not required.

2. Altered source versions must be plainly marked as such, and 
must not be misrepresented as being the original software.

3. This notice may not be removed or altered from any source 
distribution.


* Package Info *

Project URL: https://sourceforge.net/projects/tinyxml/


================================================================================
                                    Licenses
================================================================================
* Apache-2.0 *

Apache License

Version 2.0, January 2004

http://www.apache.org/licenses/

TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION

1. Definitions.

"License" shall mean the terms and conditions for use, reproduction, and distribution as defined by Sections 1 through 9 of this document.

"Licensor" shall mean the copyright owner or entity authorized by the copyright owner that is granting the License.

"Legal Entity" shall mean the union of the acting entity and all other entities that control, are controlled by, or are under common control with that entity. For the purposes of this definition, "control" means (i) the power, direct or indirect, to cause the direction or management of such entity, whether by contract or otherwise, or (ii) ownership of fifty percent (50%) or more of the outstanding shares, or (iii) beneficial ownership of such entity.

"You" (or "Your") shall mean an individual or Legal Entity exercising permissions granted by this License.

"Source" form shall mean the preferred form for making modifications, including but not limited to software source code, documentation source, and configuration files.

"Object" form shall mean any form resulting from mechanical transformation or translation of a Source form, including but not limited to compiled object code, generated documentation, and conversions to other media types.

"Work" shall mean the work of authorship, whether in Source or Object form, made available under the License, as indicated by a copyright notice that is included in or attached to the work (an example is provided in the Appendix below).

"Derivative Works" shall mean any work, whether in Source or Object form, that is based on (or derived from) the Work and for which the editorial revisions, annotations, elaborations, or other modifications represent, as a whole, an original work of authorship. For the purposes of this License, Derivative Works shall not include works that remain separable from, or merely link (or bind by name) to the interfaces of, the Work and Derivative Works thereof.

"Contribution" shall mean any work of authorship, including the original version of the Work and any modifications or additions to that Work or Derivative Works thereof, that is intentionally submitted to Licensor for inclusion in the Work by the copyright owner or by an individual or Legal Entity authorized to submit on behalf of the copyright owner. For the purposes of this definition, "submitted" means any form of electronic, verbal, or written communication sent to the Licensor or its representatives, including but not limited to communication on electronic mailing lists, source code control systems, and issue tracking systems that are managed by, or on behalf of, the Licensor for the purpose of discussing and improving the Work, but excluding communication that is conspicuously marked or otherwise designated in writing by the copyright owner as "Not a Contribution."

"Contributor" shall mean Licensor and any individual or Legal Entity on behalf of whom a Contribution has been received by Licensor and subsequently incorporated within the Work.

2. Grant of Copyright License. Subject to the terms and conditions of this License, each Contributor hereby grants to You a perpetual, worldwide, non-exclusive, no-charge, royalty-free, irrevocable copyright license to reproduce, prepare Derivative Works of, publicly display, publicly perform, sublicense, and distribute the Work and such Derivative Works in Source or Object form.

3. Grant of Patent License. Subject to the terms and conditions of this License, each Contributor hereby grants to You a perpetual, worldwide, non-exclusive, no-charge, royalty-free, irrevocable (except as stated in this section) patent license to make, have made, use, offer to sell, sell, import, and otherwise transfer the Work, where such license applies only to those patent claims licensable by such Contributor that are necessarily infringed by their Contribution(s) alone or by combination of their Contribution(s) with the Work to which such Contribution(s) was submitted. If You institute patent litigation against any entity (including a cross-claim or counterclaim in a lawsuit) alleging that the Work or a Contribution incorporated within the Work constitutes direct or contributory patent infringement, then any patent licenses granted to You under this License for that Work shall terminate as of the date such litigation is filed.

4. Redistribution. You may reproduce and distribute copies of the Work or Derivative Works thereof in any medium, with or without modifications, and in Source or Object form, provided that You meet the following conditions:

You must give any other recipients of the Work or Derivative Works a copy of this License; and
You must cause any modified files to carry prominent notices stating that You changed the files; and
You must retain, in the Source form of any Derivative Works that You distribute, all copyright, patent, trademark, and attribution notices from the Source form of the Work, excluding those notices that do not pertain to any part of the Derivative Works; and
If the Work includes a "NOTICE" text file as part of its distribution, then any Derivative Works that You distribute must include a readable copy of the attribution notices contained within such NOTICE file, excluding those notices that do not pertain to any part of the Derivative Works, in at least one of the following places: within a NOTICE text file distributed as part of the Derivative Works; within the Source form or documentation, if provided along with the Derivative Works; or, within a display generated by the Derivative Works, if and wherever such third-party notices normally appear. The contents of the NOTICE file are for informational purposes only and do not modify the License. You may add Your own attribution notices within Derivative Works that You distribute, alongside or as an addendum to the NOTICE text from the Work, provided that such additional attribution notices cannot be construed as modifying the License.

You may add Your own copyright statement to Your modifications and may provide additional or different license terms and conditions for use, reproduction, or distribution of Your modifications, or for any such Derivative Works as a whole, provided Your use, reproduction, and distribution of the Work otherwise complies with the conditions stated in this License.
5. Submission of Contributions. Unless You explicitly state otherwise, any Contribution intentionally submitted for inclusion in the Work by You to the Licensor shall be under the terms and conditions of this License, without any additional terms or conditions. Notwithstanding the above, nothing herein shall supersede or modify the terms of any separate license agreement you may have executed with Licensor regarding such Contributions.

6. Trademarks. This License does not grant permission to use the trade names, trademarks, service marks, or product names of the Licensor, except as required for reasonable and customary use in describing the origin of the Work and reproducing the content of the NOTICE file.

7. Disclaimer of Warranty. Unless required by applicable law or agreed to in writing, Licensor provides the Work (and each Contributor provides its Contributions) on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied, including, without limitation, any warranties or conditions of TITLE, NON-INFRINGEMENT, MERCHANTABILITY, or FITNESS FOR A PARTICULAR PURPOSE. You are solely responsible for determining the appropriateness of using or redistributing the Work and assume any risks associated with Your exercise of permissions under this License.

8. Limitation of Liability. In no event and under no legal theory, whether in tort (including negligence), contract, or otherwise, unless required by applicable law (such as deliberate and grossly negligent acts) or agreed to in writing, shall any Contributor be liable to You for damages, including any direct, indirect, special, incidental, or consequential damages of any character arising as a result of this License or out of the use or inability to use the Work (including but not limited to damages for loss of goodwill, work stoppage, computer failure or malfunction, or any and all other commercial damages or losses), even if such Contributor has been advised of the possibility of such damages.

9. Accepting Warranty or Additional Liability. While redistributing the Work or Derivative Works thereof, You may choose to offer, and charge a fee for, acceptance of support, warranty, indemnity, or other liability obligations and/or rights consistent with this License. However, in accepting such obligations, You may act only on Your own behalf and on Your sole responsibility, not on behalf of any other Contributor, and only if You agree to indemnify, defend, and hold each Contributor harmless for any liability incurred by, or claims asserted against, such Contributor by reason of your accepting any such warranty or additional liability.

END OF TERMS AND CONDITIONS