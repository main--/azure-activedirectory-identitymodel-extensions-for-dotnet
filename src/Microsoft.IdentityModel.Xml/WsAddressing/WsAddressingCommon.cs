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

namespace Microsoft.IdentityModel.WsAddressing
{
    /// <summary>
    /// Constants for WsAddressing 1.0.
    /// </summary>
    public static class WsAddressingConstants
    {
#pragma warning disable 1591

        public static string AddressingNone = "http://schemas.microsoft.com/ws/2005/05/addressing/none";
        /// <summary>
        /// Elements that can be in a WsAddressing ns
        /// </summary>
        public static class Elements
        {
            //public static string Action => WsAddressingConstants.Elements.Action;
            //public static string Address => WsAddressingConstants.Elements.Address;
            //public static string EndpointReference => WsAddressingConstants.Elements.EndpointReference;
            //public static string Fault => WsAddressingConstants.Elements.Fault;
            //public static string FaultTo => WsAddressingConstants.Elements.FaultTo;
            //public static string From => WsAddressingConstants.Elements.From;
            //public static string MessageId => WsAddressingConstants.Elements.MessageId;
            //public static string ReplyTo => WsAddressingConstants.Elements.ReplyTo;
            //public static string RelatesTo => WsAddressingConstants.Elements.RelatesTo;
            //public static string To => WsAddressingConstants.Elements.To;

            public const string Action = "Action";
            public const string Address = "Address";
            public const string EndpointReference = "EndpointReference";
            public const string Fault = "Fault";
            public const string FaultTo = "FaultTo";
            public const string From = "From";
            public const string MessageId = "MessageId";
            public const string ReplyTo = "ReplyTo";
            public const string RelatesTo = "RelatesTo";
            public const string To = "To";
        }
#pragma warning restore 1591

    }
}
 
