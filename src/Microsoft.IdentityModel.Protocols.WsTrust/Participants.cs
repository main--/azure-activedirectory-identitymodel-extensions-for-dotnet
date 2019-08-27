//-----------------------------------------------------------------------
// <copyright file="Participants.cs" company="Microsoft">
//     Copyright (c) Microsoft Corporation.  All rights reserved.
// </copyright>
//-----------------------------------------------------------------------

using System.Collections.Generic;
using System.Collections.ObjectModel;
using Microsoft.IdentityModel.Logging;
using Microsoft.IdentityModel.WsAddressing;

namespace Microsoft.IdentityModel.Protocols.WsTrust
{
    /// <summary>
    /// Contains information for the 'Participants' element.
    /// </summary>
    public class Participants
    {
        /// <summary>
        /// 
        /// </summary>
        /// <param name="primary"></param>
        public Participants(EndpointReference primary)
        {
            Primary = primary ?? throw LogHelper.LogArgumentNullException(nameof(primary));
        }

        /// <summary>
        /// Gets the Primary user of the Issued Token.
        /// </summary>
        public EndpointReference Primary { get; }

        /// <summary>
        /// Gets the list of Participants who are allowed to use
        /// the token.
        /// </summary>
        public ICollection<EndpointReference> Participant { get; } = new Collection<EndpointReference>();
    }
}
