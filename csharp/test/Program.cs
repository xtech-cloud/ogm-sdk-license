using System;

namespace test
{
    class Program
    {
        static void Main(string[] args)
        {
            string[] lines = System.IO.File.ReadAllLines("C:\\Users\\easlee\\AppData\\LocalLow\\MeeX\\MeeTouch\\app.cer");
            int code = XTC.OGM.SDK.License.Verify(lines, "a0dd390f464768319293d47fca22e1c3", "3f80c78f4fa16d2dd52709dea62b6bd8", "B66B52F5F1F45C75E4F1837A1C7E9CA9");
            Console.WriteLine(code);
        }
    }
}
