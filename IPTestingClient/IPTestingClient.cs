using AppDLLStuffNS;
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Runtime.Serialization.Formatters.Binary;
using System.Threading;
using System.Threading.Tasks;
using System.Text;
using System.Security.Cryptography;

namespace IPTestingClientNS
{
    public static class IPTestingClient
    {
        static void Main(string[] args)
        {
            Dictionary<string, string> parameters = new Dictionary<string, string>();
            ProgramArgs.ParseArgs(args, '-', parameters);
            var tokenSource = new CancellationTokenSource();
            string username = ProgramArgs.ParameterElseEntry(parameters, "username", "Enter a username:");
            byte[] encryptionKey = MD5.Create().ComputeHash(Encoding.UTF8.GetBytes(ProgramArgs.ParameterElseEntry(parameters, "encryptionkey", "Please enter the encryption key you want to use.")));
            // First use of a non-short-circuiting boolean AND operator!
            //if (parameters.TryGetValue("ip:port", out string ipPortArg) & IPParser.TryParseIPEndPoint(ipPortArg, out IPEndPoint endPoint)) Console.WriteLine($"ip:port = {ipPortArg}");
            IPEndPoint endPoint = ProgramArgs.ParseParameterElseEntry(parameters, "ip:port", new ProgramArgs.TryParseFunc<IPEndPoint>(IPParser.TryParseDnsOrIPEndpoint), "Enter an ip address and port in the format \"127.0.0.1:25565\":", "The entered IP:Port address was in an incorrect format. Please try again.");
            int updateInterval = ProgramArgs.ParseParameterElseEntry(parameters, "updateinterval", new ProgramArgs.TryParseFunc<int>(int.TryParse), "Please enter the interval (in milliseconds) for updating the chat log.", "Invalid input. Please try again.");
            var rijndael = Rijndael.Create();
            rijndael.Key = encryptionKey;
            rijndael.IV = encryptionKey;
            var encryptor = rijndael.CreateEncryptor();
            var decryptor = rijndael.CreateDecryptor();

            BinaryFormatter binForm = new BinaryFormatter();
            
            CryptoTcpClient server;
            while (true)
            {
                try
                {
                    TcpClient incompleteServer = new TcpClient();
                    incompleteServer.Connect(endPoint);
                    server = new CryptoTcpClient(incompleteServer, encryptor, decryptor);
                    Console.WriteLine("Connection accepted.");
                    break;
                }
                catch (Exception e)
                {
                    Console.WriteLine(e.Message);
                    Console.WriteLine("The given IP:Port address failed to connect to a server. Please enter a new one or try again.");
                }
                while (!IPEndPoint.TryParse(Console.ReadLine(), out endPoint)) Console.WriteLine("The entered IP:Port address was in an incorrect format. Please try again.");
            }
            ReadAllPacketsTask(server, binForm, updateInterval, tokenSource.Token);
            Console.WriteLine("You may now begin sending messages.");
            try
            {
                string message = string.Empty;
                while (true)
                {
                    message = Console.ReadLine();
                    if (string.IsNullOrWhiteSpace(message)) continue;
                    server.EncryptAndSendPacket(new Packet(username, message), binForm);
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }

            Console.WriteLine("Press any key to exit...");
            Console.Read();
        }

        public static Task ReadAllPacketsTask(CryptoTcpClient server, BinaryFormatter binForm, int IntervalMilliseconds, CancellationToken token)
        {
            return Task.Factory.StartNew(() =>
            {
                while (!token.IsCancellationRequested)
                {
                    Packet packet = server.GetAndDecryptPacket(binForm);
                    if (packet != null)
                    {
                        ConsoleExtensions.WriteToConsole(packet.userName, packet.message);
                    }
                    if (IntervalMilliseconds > 0)
                    {
                        Thread.Sleep(IntervalMilliseconds);
                    }
                }
            }, token, TaskCreationOptions.LongRunning, TaskScheduler.Default);
        }
    }
}
