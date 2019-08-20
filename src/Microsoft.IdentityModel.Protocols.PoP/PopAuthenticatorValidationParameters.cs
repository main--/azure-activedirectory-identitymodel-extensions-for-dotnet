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

using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Logging;
using System;

namespace Microsoft.IdentityModel.Protocols.PoP
{
    /// <summary>
    /// 
    /// </summary>
    /// <param name="jwtAuthenticator"></param>
    /// <returns></returns>
    public delegate void AuthenticatorReplayValidator(JsonWebToken jwtAuthenticator);

    /// <summary>
    /// 
    /// </summary>
    public class PopAuthenticatorValidationParameters
    {
        /// <summary>
        ///
        /// </summary>
        public PopAuthenticatorVersion PopAuthenticatorVersion { get; set; } = PopAuthenticatorVersion.Default;

        /// <summary>
        /// </summary>
        public static readonly TimeSpan DefaultClockSkew = TimeSpan.FromMinutes(1);

        private TimeSpan _clockSkew = DefaultClockSkew;

        /// <summary>
        /// 
        /// </summary>
        public TimeSpan ClockSkew
        {
            get
            {
                return _clockSkew;
            }

            set
            {
                if (value < TimeSpan.Zero)
                    throw LogHelper.LogExceptionMessage(new ArgumentOutOfRangeException(nameof(value)));

                _clockSkew = value;
            }
        }

        /// <summary>
        /// 
        /// </summary>
        public static readonly TimeSpan DefaultAuthenticatorLifetime = TimeSpan.FromMinutes(5);

        private TimeSpan _authenticatorLifetime = DefaultAuthenticatorLifetime;

        /// <summary>
        /// 
        /// </summary>
        public TimeSpan AuthenticatorLifetime
        {
            get
            {
                return _authenticatorLifetime;
            }

            set
            {
                if (value < TimeSpan.Zero)
                    throw LogHelper.LogExceptionMessage(new ArgumentOutOfRangeException(nameof(value)));

                _authenticatorLifetime = value;
            }
        }

        /// <summary>
        /// Gets or sets a value indicating whether the <see cref="PopConstants.ClaimTypes.Ts"/> claim should be validated or not.
        /// </summary>
        public bool ValidateTs { get; set; } = true;

        /// <summary>
        /// Gets or sets a value indicating whether the <see cref="PopConstants.ClaimTypes.M"/> claim should be validated or not.
        /// </summary>
        public bool ValidateM { get; set; } = false;

        /// <summary>
        /// Gets or sets a value indicating whether the <see cref="PopConstants.ClaimTypes.U"/> claim should be validated or not.
        /// </summary>
        public bool ValidateU { get; set; } = false;

        /// <summary>
        /// Gets or sets a value indicating whether the <see cref="PopConstants.ClaimTypes.P"/> claim should be validated or not.
        /// </summary>
        public bool ValidateP { get; set; } = false;

        /// <summary>
        /// Gets or sets a value indicating whether the <see cref="PopConstants.ClaimTypes.Q"/> claim should be validated or not.
        /// </summary>
        public bool ValidateQ { get; set; } = false;

        /// <summary>
        /// Gets or sets a value indicating whether the <see cref="PopConstants.ClaimTypes.H"/> claim should be validated or not.
        /// </summary>
        public bool ValidateH { get; set; } = false;

        /// <summary>
        /// Gets or sets a value indicating whether the <see cref="PopConstants.ClaimTypes.B"/> claim should be validated or not.
        /// </summary>
        public bool ValidateB { get; set; } = false;

        /// <summary>
        /// Gets or sets a delegate that will be used to check if the authenticator is replayed.
        /// </summary>
        public AuthenticatorReplayValidator AuthenticatorReplayValidator { get; set; }
    }
}
