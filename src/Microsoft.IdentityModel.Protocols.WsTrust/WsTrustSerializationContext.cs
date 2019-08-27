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

#pragma warning disable 1591

using System;

namespace Microsoft.IdentityModel.Protocols.WsTrust
{
    /// <summary>
    /// Used to remember the prefix, namespace to use / expect when reading and writing WsTrust Requests and Responses.
    /// </summary>
    public class WsTrustSerializationContext
    {
        private readonly string _issue;
        private readonly string _namespace;
        private readonly string _prefix;
        private readonly string _validate;

        //private Func<string> _rstIssue; 
        //private Func<string> _rstrIssue;
        //private Func<string> _rstrcIssueFinal;

        //private Func<string> _renew; 
        //private Func<string> _rstRenew; 
        //private Func<string> _rstrRenew; 
        //private Func<string> _rstsRenewFinal; 

        //private Func<string> _cancel; 
        //private Func<string> _rstCancel; 
        //private Func<string> _rstrCancel; 
        //private Func<string> _rstrCancelFinal;

        ////private Func<string> _validate; 
        //private Func<string> _rstValidate; 
        //private Func<string> _rstrValidate;
        //private Func<string> _rstrValidateFinal;

        //private Func<string> _rstsStatus;

        /// <summary>
        /// Initializes an instance <see cref="WsTrustSerializationContext"/>
        /// </summary>
        public WsTrustSerializationContext(WsTrustVersion wsTrustVersion)
        {
            WsTrustVersion = wsTrustVersion;

            switch (wsTrustVersion)
            {
                case WsTrustVersion.WsTrust13:
                case WsTrustVersion.Unknown:
                default:
                {
                    _issue = WsTrust13Constants.RequestTypes.Issue;
                    _namespace = WsTrust13Constants.Namespace;
                    _prefix =  WsTrust13Constants.Prefix;
                    _validate = WsTrust13Constants.RequestTypes.Validate;
                    break;
                }

                case WsTrustVersion.WsTrust14:
                {
                    _issue = WsTrust13Constants.RequestTypes.Issue;
                    _namespace = WsTrust14Constants.Namespace;
                    _prefix = WsTrust14Constants.Prefix;
                    _validate = WsTrust13Constants.RequestTypes.Validate;
                    break;
                }

                case WsTrustVersion.WsTrust2005:
                {
                    _issue = WsTrust2005Constants.RequestTypes.Issue;
                    _namespace = WsTrust2005Constants.Namespace;
                    _prefix =  WsTrust2005Constants.Prefix;
                    _validate = WsTrust13Constants.RequestTypes.Validate;
                    break;
                }
            }
        }

        public string Issue => _issue;

        public string Namespace => _namespace;

        public string Prefix => _prefix;

        public string Validate => _validate;

        public WsTrustVersion WsTrustVersion { get; }

        //public string RSTIssue =
        //public string RSTRIssue =
        //public string RSTRCIssueFinal =

        //public string Renew =
        //public string RSTRenew =
        //public string RSTRRenew =
        //public string RSTRRenewFinal =

        //public string Cancel =
        //public string RSTCancel =
        //public string RSTRCancel =
        //public string RSTRCancelFinal =

        //public string Validate =
        //public string RSTValidate =
        //public string RSTRValidate =
        //public string RSTRValidateFinal =

        //public string RSTSStatus = 
    }
}
