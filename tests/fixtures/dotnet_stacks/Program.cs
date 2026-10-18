using System;
using System.Threading;
class ManagedStacks {
    static void Leaf() { Console.WriteLine("DOTNET_READY"); Thread.Sleep(30000); }
    static void Caller() { Leaf(); }
    static void Main() { Caller(); }
}
