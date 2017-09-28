using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Runtime.Serialization;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using ESolutions.DarkBird.Mobile.GCS.Interfaces;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;

namespace ESolutions.Xamarin
{
	/// <summary>
	/// HttpClient using the network to communicate.
	/// </summary>
	/// <seealso cref="ESolutions.DarkBird.Mobile.GCS.Interfaces.IHttpClient" />
	public class NetworkHttpClient : IHttpClient
	{
		#region HmacSha256
		public class HmacSha256
		{
			//Fields
			#region key
			private Byte[] key = null;
			#endregion

			//Constructors
			#region HmacSha256
			public HmacSha256(Byte[] key)
			{
				this.key = key;
			}
			#endregion

			//Methods
			#region ComputeHash
			public Byte[] ComputeHash(Byte[] bytes)
			{
				var hmac = new HMac(new Sha256Digest());
				hmac.Init(new KeyParameter(key));
				Byte[] result = new Byte[hmac.GetMacSize()];

				hmac.BlockUpdate(bytes, 0, bytes.Length);
				hmac.DoFinal(result, 0);

				return result;
			}
			#endregion
		}
		#endregion

		//Fields
		#region client
		/// <summary>
		/// The http client.
		/// </summary>
		private HttpClient client = null;
		#endregion

		#region url
		private String url = "https://myservice.servicebus.windows.net/";
		#endregion

		#region sasKey
		private String sasKey = "the private key from the azure portal";
		#endregion

		//Constructors
		#region NetworkHttpClient
		/// <summary>
		/// Initializes a new instance of the <see cref="NetworkHttpClient"/> class.
		/// </summary>
		public NetworkHttpClient(String url, String sasKey)
		{
			this.client = new HttpClient()
            {
				Timeout = new TimeSpan(0, 0, 3),
			};

			this.url = url;
			this.sasKey = sasKey;
		}
		#endregion

		//Methods
		#region Dispose
		/// <summary>
		/// Disposes this instance.
		/// </summary>
		public void Dispose()
		{
			this.client?.Dispose();
		}
		#endregion

		#region PostAsync
		public async Task PostAsync(String data)
		{
			MemoryStream contentStream = new MemoryStream();
			DataContractSerializer serializer = new DataContractSerializer(typeof(String));
			XmlDictionaryWriter writer = XmlDictionaryWriter.CreateBinaryWriter(contentStream);
			writer.WriteStartDocument();
			serializer.WriteStartObject(writer, data);
			serializer.WriteObjectContent(writer, data);
			serializer.WriteEndObject(writer);
			writer.Flush();

			String fullAddress = "https://darkbird.servicebus.windows.net/checkpointtouches/messages";
			this.client.DefaultRequestHeaders.TryAddWithoutValidation("Content-Type", "application/atom+xml;type=entry;charset=utf-8");
			this.client.DefaultRequestHeaders.TryAddWithoutValidation("Authorization", GetSASToken(this.url, "RootManageSharedAccessKey", this.sasKey));
			this.client.DefaultRequestHeaders.TryAddWithoutValidation("BrokerProperties", @"{ ""MessageId"": """ + Guid.NewGuid().ToString() + @"""}");
			var result = await this.client.PostAsync(fullAddress, new StreamContent(new System.IO.MemoryStream(contentStream.ToArray())));

			System.Diagnostics.Debug.WriteLine(result.StatusCode.ToString());
		}
		#endregion

		#region GetSASToken
		public static String GetSASToken(String baseAddress, String SASKeyName, String SASKeyValue)
		{
			TimeSpan fromEpochStart = DateTime.UtcNow - new DateTime(1970, 1, 1);
			String expiry = Convert.ToString((Int32)fromEpochStart.TotalSeconds + 3600);
			String stringToSign = WebUtility.UrlEncode(baseAddress) + "\n" + expiry;

			HmacSha256 hmac = new HmacSha256(Encoding.UTF8.GetBytes(SASKeyValue));
			String signature = Convert.ToBase64String(hmac.ComputeHash(Encoding.UTF8.GetBytes(stringToSign)));

			String sasToken = String.Format(CultureInfo.InvariantCulture, "SharedAccessSignature sr={0}&sig={1}&se={2}&skn={3}", WebUtility.UrlEncode(baseAddress), WebUtility.UrlEncode(signature), expiry, SASKeyName);
			return sasToken;
		}
		#endregion
	}
}
