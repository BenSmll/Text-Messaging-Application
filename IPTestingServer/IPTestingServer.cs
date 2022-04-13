using System;
using System.Threading;
using System.Threading.Tasks;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Text;
using AppDLLStuffNS;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;
using System.IO;

namespace IPTestingServerNS
{
    public static class IPTestingServer
    {
        static void Main(string[] args)
        {
            NetworkStuff.WriteAllNetworkInformation();
            Dictionary<string, string> parameters = new Dictionary<string, string>();
            ProgramArgs.ParseArgs(args, '-', parameters);
            var tokenSource = new CancellationTokenSource();
            //parameters.TryGetValue("clientCheckInterval", out string value) ? int.TryParse(value, out int result) ? result : 1000 : 1000
            ProgramArgs.TryParseFunc<int> intTryParseFunc = new ProgramArgs.TryParseFunc<int>(int.TryParse);
            int port = ProgramArgs.ParseParameterElseEntry(parameters, "port", intTryParseFunc, "Please enter a valid port.", "Invalid input. Please try again.", IPEndPoint.MinPort, IPEndPoint.MaxPort);
            int maxUsers = ProgramArgs.ParseParameterElseEntry(parameters, "maxusers", intTryParseFunc, "Please enter the maximum number of users you want in your server.", "Invalid input. Please try again.");
            int clientCheckInterval = ProgramArgs.ParseParameterElseEntry(parameters, "clientcheckinterval", intTryParseFunc, "Please enter the interval (in milliseconds) for checking for new connecting clients.", "Invalid input. Please try again.");
            int updateInterval = ProgramArgs.ParseParameterElseEntry(parameters, "updateinterval", intTryParseFunc, "Please enter the interval (in milliseconds) for updating the chat log.", "Invalid input. Please try again.");
            // Make MD5 from string, pad extra bits if < 128, cut excess bits if > 128
            // As it turns out, MD5 makes a 128-bit hash every time anyway, so that's unnecessary.
            byte[] encryptionKey = MD5.Create().ComputeHash(Encoding.UTF8.GetBytes(ProgramArgs.ParameterElseEntry(parameters, "encryptionkey", "Please enter the encryption key you want to use.")));
            //Console.WriteLine(string.Join(' ', encryptionKey));
            //string certName = ProgramArgs.ParameterElseEntry(parameters, "X509certificate", "Please enter a valid X509 Certificate name.");
            //var certificate = Crypto.GetCertificateFromStore(certName);
            Rijndael rijndael = Rijndael.Create();
            rijndael.Key = encryptionKey;
            rijndael.IV = encryptionKey;
            var encryptor = rijndael.CreateEncryptor();
            var decryptor = rijndael.CreateDecryptor();

            Console.WriteLine("Server setup complete. Now accepting clients...");
            BinaryFormatter binForm = new BinaryFormatter();
            List<CryptoTcpClient> clients = new List<CryptoTcpClient>();
            AcceptAllClientsTask(port, maxUsers, clients, encryptor, decryptor, clientCheckInterval, tokenSource.Token);
            List<Packet> incomingPackets;
            while (true)
            {
                incomingPackets = GetPacketsFromAllClients(clients, binForm, tokenSource.Token);
                if (incomingPackets.Count > 0)
                {
                    //SavePacket(incomingPackets[0]);
                    // Re-tested with encryption in CryptoTcpClient GetAndDecryptPackets method. Text is completely unreadable if intercepted. Perfect!
                    foreach (Packet packet in incomingPackets)
                    {
                        ConsoleExtensions.WriteToConsole(packet.userName, packet.message);
                    }
                    SendPacketsToClients(clients, incomingPackets, binForm, tokenSource.Token);
                }
                else if (parameters.ContainsKey("verbose"))
                {
                    Console.WriteLine("No messages recieved.");
                }
                if (updateInterval > 0)
                {
                    Thread.Sleep(updateInterval);
                }
            }
        }

        public static void SavePacket(Packet packet)
        {
            string fileName = packet.userName + ".txt";
            using FileStream fs = File.OpenWrite(Path.Combine("", fileName));
            BinaryFormatter b = new BinaryFormatter();
            b.Serialize(fs, packet);
        }

        public static void AcceptAllClients(int port, int acceptableSockets, List<TcpClient> client)
        {
            TcpListener listener = new TcpListener(IPAddress.Any, port);
            listener.Start(acceptableSockets);
            for (int i = 0; i < acceptableSockets; i++)
            {
                try
                {
                    client.Add(listener.AcceptTcpClient());
                    Console.WriteLine("Connection accepted from new client.");
                }
                catch (Exception e)
                {
                    Console.WriteLine(e.Message);
                }
            }
        }

        public static Task AcceptAllClientsTask(int port, int acceptableSockets, List<CryptoTcpClient> clients, ICryptoTransform encrypt, ICryptoTransform decrypt, int intervalMilliseconds, CancellationToken token)
        {
            return Task.Factory.StartNew(() =>
            {
                TcpListener listener = new TcpListener(IPAddress.Any, port);
                listener.Start(acceptableSockets);
                while (!token.IsCancellationRequested)
                {
                    try
                    {
                        clients.Add(new CryptoTcpClient(listener.AcceptTcpClient(), encrypt, decrypt));
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine(e.Message);
                    }
                    if (intervalMilliseconds > 0)
                    {
                        Thread.Sleep(intervalMilliseconds);
                    }
                }
            }, token, TaskCreationOptions.LongRunning, TaskScheduler.Default);
        }

        //public static Packet GetPacketFromClient(TcpClient client, ICryptoTransform transform, BinaryFormatter binForm, CancellationToken token)
        //{
        //    if (client.Available > 0 && !token.IsCancellationRequested)
        //    {
        //        try
        //        {
        //            return (Packet)binForm.Deserialize(new CryptoStream(client.GetStream(), transform, CryptoStreamMode.Read));
        //        }
        //        catch (Exception e)
        //        {
        //            Console.WriteLine(e.Message);
        //        }
        //    }
        //    return null;
        //}

        public static List<Packet> GetPacketsFromAllClients(List<CryptoTcpClient> clients, BinaryFormatter binForm, CancellationToken token)
        {
            List<Packet> allPackets = new List<Packet>();
            foreach (var client in clients)
            {
                Packet packet = client.GetAndDecryptPacket(binForm);
                if (packet != null)
                {
                    allPackets.Add(packet);
                }
            }
            return allPackets;
        }

        public static void SendPacketsToClients(List<CryptoTcpClient> clients, List<Packet> packets, BinaryFormatter binForm, CancellationToken token)
        {
            foreach (var client in clients)
            {
                foreach (Packet packet in packets)
                {
                    if (!token.IsCancellationRequested)
                    {
                        try
                        {
                            client.EncryptAndSendPacket(packet, binForm);
                        }
                        catch (Exception e)
                        {
                            Console.WriteLine(e.Message);
                        }
                    }
                }
            }
        }
    }
}
