//------------------------------------------------------------------------------
//
// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
//------------------------------------------------------------------------------

using Microsoft.IdentityModel.TestUtils;
using Microsoft.IdentityModel.Tokens.Saml2;
using System;
using System.IO;
using System.Text;
using System.Xml;
using Xunit;

#pragma warning disable CS3016 // Arrays as attribute arguments is not CLS-compliant

namespace Microsoft.IdentityModel.Protocols.WsTrust.Tests
{
    public class WsTrustMessageTests
    {
        [Fact]
        public void GetSets()
        {
        }

        [Theory, MemberData(nameof(SerailizeWsTrustRequestTheoryData))]
        public void SerializeWsTrustRequest(WsTrustTheoryData theoryData)
        {
            var context = TestUtilities.WriteHeader($"{this}.SerializeWsTrustRequest", theoryData);

            try
            {
                var memeoryStream = new MemoryStream();
                var xmlWriter = XmlDictionaryWriter.CreateTextWriter(memeoryStream);
                var serializer = new WsTrustSerializer();
                serializer.WriteXml(xmlWriter, theoryData.WsTrustRequest);
                xmlWriter.Flush();
                var xml = Encoding.UTF8.GetString(memeoryStream.ToArray());

                theoryData.ExpectedException.ProcessNoException(context);

            }
            catch (Exception ex)
            {
                theoryData.ExpectedException.ProcessException(ex, context);
            }

            TestUtilities.AssertFailIfErrors(context);
        }

        public static TheoryData<WsTrustTheoryData> SerailizeWsTrustRequestTheoryData
        {
            get
            {
                return new TheoryData<WsTrustTheoryData>
                {
                    new WsTrustTheoryData
                    {
                        First = true,
                        WsTrustRequest = new WsTrustRequest(WsTrustRequestType.Issue, WsTrustVersion.WsTrust13)
                        {
                            AppliesTo = WsTrustMessageTestDefaults.EndpointReference,
                            Context = "Context",
                            TokenType = Saml2Constants.OasisWssSaml2TokenProfile11
                        },
                        TestId = "SerializeWsTrustRequestTheoryData1"
                    }
                };
            }
        }
    }

    public class WsTrustTheoryData : TheoryDataBase
    {
        public object CompareTo { get; set; }

        public WsTrustRequest WsTrustRequest { get; set; }
    }
}

#pragma warning restore CS3016 // Arrays as attribute arguments is not CLS-compliant
