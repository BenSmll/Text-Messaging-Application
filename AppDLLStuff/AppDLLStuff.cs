using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text.RegularExpressions;
using System.Security.Cryptography;
using System.Net.Sockets;
using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography.X509Certificates;

namespace AppDLLStuffNS
{
	[Serializable]
	public class Packet
	{
		public string userName;
		public string message;
		public Packet() { }
		public Packet(string userName, string message)
		{
			this.userName = userName;
			this.message = message;
		}
	}

	public static class ConsoleExtensions
	{
		public static void WriteToConsole(string sourceName, string text)
		{
			Console.WriteLine($"{sourceName}> {text}");
		}
		public static string ReadFromConsole(string prompt = default)
		{
			Console.Write($"{prompt}: ");
			string input;
			do
			{
				input = Console.ReadLine();
			}
			while (string.IsNullOrWhiteSpace(input));
			return input;
		}
	}

	public static class NetworkStuff
	{
		public static void WriteAllNetworkInformation()
		{
			Console.WriteLine("Private addresses for this device:");
			foreach (IPAddress ip in Dns.GetHostEntry(IPAddress.Loopback).AddressList)
			{
				Console.WriteLine(ip.ToString());
			}
			Console.WriteLine($"Public addresses for this device:\n{GetPublicIP()}\n");
		}
		public static string GetPublicIP()
		{
			try
			{
				return new WebClient().DownloadString("http://icanhazip.com").Trim();
			}
			catch (Exception e)
			{
				Console.WriteLine(e.Message);
			}
			return null;
		}
	}

	public static class IPParser
	{
		public static Regex ipFormat = new Regex(@"\A\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d{1,5}\z");
		public static bool IsValidIPFormat(string s)
		{
			return ipFormat.IsMatch(s);
		}

		public static bool TryParseDnsOrIPEndpoint(string s, out IPEndPoint endPoint)
		{
			if (IPEndPoint.TryParse(s, out endPoint)) return true;
			else
			{
				string[] splitAddress = s.Split(':', StringSplitOptions.RemoveEmptyEntries);
				string addressNoPort = string.Join(null, splitAddress.Take(splitAddress.Length - 1));
				if (int.TryParse(splitAddress[^1], out int port))
				{
					try
					{
						endPoint = new IPEndPoint(Dns.GetHostAddresses(addressNoPort)[0], port);
						return true;
					}
					catch (Exception e)
					{
						Console.WriteLine(e.Message);
						return false;
					}
				}
				else
				{
					endPoint = null;
					return false;
				}
			}
		}
	}
	public static class ProgramArgs
	{
		public static void ParseArgs(string[] args, string keyIdentifier, Dictionary<string, string> parameters)
		{
			string key;
			string value;
			for (int i = 0; i < args.Length; i++)
			{
				if (args[i].StartsWith(keyIdentifier))
				{
					key = args[i].Substring(keyIdentifier.Length);
				}
				else continue;
				if (i + 1 < args.Length && !args[i + 1].StartsWith(keyIdentifier))
				{
					value = args[i + 1];
				}
				else value = null;
				parameters.Add(key, value);
			}
		}
		public static void ParseArgs(string[] args, char keyIdentifier, Dictionary<string, string> parameters)
		{
			ParseArgs(args, keyIdentifier.ToString(), parameters);
		}

		public static string ParameterElseEntry(Dictionary<string, string> parameters, string parameterToCheck, string prompt)
		{
			if (!parameters.TryGetValue(parameterToCheck, out string parameterArg) || parameterArg == null)
			{
				Console.WriteLine(prompt);
				parameterArg = Console.ReadLine();
			}
			Console.WriteLine($"{parameterToCheck} = {parameterArg}");
			return parameterArg;
		}

		//public static int ParseIntParameterElseEntry(Dictionary<string, string> parameters, string parameterToCheck, string prompt, string failPrompt, int min = int.MinValue, int max = int.MaxValue)
		//{
		//    if (!parameters.TryGetValue(parameterToCheck, out string parameterArg) || parameterArg == null || !int.TryParse(parameterArg, out int output)) Console.WriteLine(prompt);
		//    else
		//    {
		//        Console.WriteLine($"{parameterToCheck} = {output}");
		//        return output;
		//    }
		//    while (true)
		//    {
		//        while (!int.TryParse(Console.ReadLine(), out output)) Console.WriteLine(failPrompt);
		//        if (output >= min && output <= max)
		//        {
		//            break;
		//        }
		//        Console.WriteLine(failPrompt);
		//    }
		//    Console.WriteLine($"{parameterToCheck} = {output}");
		//    return output;
		//}

		public delegate bool TryParseFunc<T>(string s, out T result);
		public static T ParseParameterElseEntry<T>(Dictionary<string, string> parameters, string parameterToCheck, TryParseFunc<T> tryParseFunc, string prompt, string failPrompt)
		{
			if (!parameters.TryGetValue(parameterToCheck, out string parameterArg) || parameterArg == null || !tryParseFunc(parameterArg, out T output)) Console.WriteLine(prompt);
			else
			{
				Console.WriteLine($"{parameterToCheck} = {output}");
				return output;
			}
			while (!tryParseFunc(Console.ReadLine(), out output)) Console.WriteLine(failPrompt);
			Console.WriteLine($"{parameterToCheck} = {output}");
			return output;
		}
		public static T ParseParameterElseEntry<T>(Dictionary<string, string> parameters, string parameterToCheck, TryParseFunc<T> tryParseFunc, string prompt, string failPrompt, T min, T max) where T : IComparable<T>
		{
			if (!parameters.TryGetValue(parameterToCheck, out string parameterArg) || parameterArg == null || !tryParseFunc(parameterArg, out T output)) Console.WriteLine(prompt);
			else
			{
				Console.WriteLine($"{parameterToCheck} = {output}");
				return output;
			}
			while (true)
			{
				while (!tryParseFunc(Console.ReadLine(), out output)) Console.WriteLine(failPrompt);
				if (output.CompareTo(min) >= 0 && output.CompareTo(max) <= 0)
				{
					break;
				}
				Console.WriteLine(failPrompt);
			}
			Console.WriteLine($"{parameterToCheck} = {output}");
			return output;
		}

		//public static T Special<T>(string parameterToCheck, Delegate tryParseFunc)
		//{
		//    T output = (T)tryParseFunc.DynamicInvoke(parameterToCheck);
		//    ABC("egg", typeof(ArgumentHandler));
		//    return output;
		//}
		//public static int ABC(string s, Type t)
		//{
		//    t.Assembly;
		//    return 5;
		//}
	}

	public class CryptoTcpClient
	{
		public CryptoTcpClient(TcpClient client, ICryptoTransform encryptor, ICryptoTransform decryptor)
		{
			this.client = client;
			this.encryptor = encryptor;
			this.decryptor = decryptor;
		}

		public readonly TcpClient client;
		private readonly ICryptoTransform encryptor;
		private readonly ICryptoTransform decryptor;
		// Throws 'Stream does not support writing' exception when attempting .SetLength(0)
		//private readonly MemoryStream bufferStream = new MemoryStream();

		public void EncryptAndSendPacket(Packet packet, BinaryFormatter binForm)
		{
			try
			{
				using var memoryStream = new MemoryStream();
				using var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write);
				binForm.Serialize(cryptoStream, packet);
				cryptoStream.FlushFinalBlock();
				memoryStream.Position = 0;
				memoryStream.CopyTo(client.GetStream());
			}
			catch (Exception e)
			{
				Console.WriteLine(e.Message);
			}
		}

		public Packet GetAndDecryptPacket(BinaryFormatter binForm)
		{
			if (client.Available > 0)
			{
				try
				{
					using var memoryStream = new MemoryStream();
					using var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Write);
					//using var fs = File.OpenWrite("output.txt");
					byte[] buffer;
					int bytesRec;
					while (client.Available > 0)
					{
						buffer = new byte[1024];
						bytesRec = client.GetStream().Read(buffer, 0, buffer.Length);
						//fs.Write(buffer);
						cryptoStream.Write(buffer, 0, bytesRec);
					}
					cryptoStream.FlushFinalBlock();
					memoryStream.Position = 0;
					return (Packet)binForm.Deserialize(memoryStream);
				}
				catch (Exception e)
				{
					Console.WriteLine(e.Message);
				}
			}
			return null;
		}

		//public Stream GetDecryptStream()
		//{
		//	var memoryStream = new MemoryStream();
		//	var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Write);
		//	byte[] buffer;
		//	List<byte> allbytes = new List<byte>();
		//	int bytesRec = 0;
		//	while (client.Available > 0)
		//	{
		//		buffer = new byte[1024];
		//		bytesRec += client.GetStream().Read(buffer, 0, buffer.Length);
		//		allbytes.AddRange(buffer);
		//	}
		//	cryptoStream.Write(allbytes.Take(bytesRec).ToArray());
		//	memoryStream.Position = 0;
		//	return memoryStream;
		//}
		//public Stream GetEncryptStream()
		//{
		//	//var memoryStream = new MemoryStream();
		//	//using var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write);
		//	////Client hangs. Maybe because it's trying to copy the entirety of the NetworkStream, but it doesn't have an end?
		//	////client.GetStream().CopyTo(cryptoStream);
		//	//byte[] buffer;
		//	//List<byte> allbytes = new List<byte>();
		//	//int bytesRec = 0;
		//	//while (client.Available > 0)
		//	//{
		//	//	buffer = new byte[1024];
		//	//	bytesRec += client.GetStream().Read(buffer, 0, buffer.Length);
		//	//	allbytes.AddRange(buffer);
		//	//}
		//	//cryptoStream.Write(allbytes.Take(bytesRec).ToArray());
		//	//return memoryStream;
		//	var stream = new CryptoStream(client.GetStream(), encryptor, CryptoStreamMode.Write);
		//	return stream;
		//}
	}

	//public class SsLClient
	//{
	//    public SsLClient(TcpClient client)
	//    {
	//        this.client = client;
	//        sslStream = new SslStream(client.GetStream(), false);
	//    }

	//    private readonly SslStream sslStream;
	//    public readonly TcpClient client;

	//    public SslStream GetSslStream()
	//    {
	//        return sslStream;
	//    }
	//}

	public static class Crypto
	{
		public static X509Certificate2 GetCertificateFromStore(string certName)
		{
			X509Store store = new X509Store(StoreLocation.CurrentUser);
			try
			{
				store.Open(OpenFlags.ReadOnly);
				X509Certificate2Collection certCollection = store.Certificates;
				var currentCerts = certCollection.Find(X509FindType.FindByTimeValid, DateTime.Now, false);
				var signingCerts = currentCerts.Find(X509FindType.FindBySubjectDistinguishedName, certName, false);
				if (signingCerts.Count == 0)
				{
					return null;
				}
				else
				{
					return signingCerts[0];
				}
			}
			catch (Exception e)
			{
				Console.WriteLine(e.Message);
			}
			finally
			{
				store.Close();
			}
			return null;
		}
	}
}
