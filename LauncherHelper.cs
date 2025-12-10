using System.Runtime.InteropServices;

namespace DummyBackgroundProcess
{
    class Program
    {
        [StructLayout(LayoutKind.Sequential)]
        public struct MSG
        {
            public IntPtr hwnd;
            public uint message;
            public IntPtr wParam;
            public IntPtr lParam;
            public uint time;
            public int pt_x; 
            public int pt_y;
        }
        
        [DllImport("user32.dll")]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool PeekMessage(out MSG lpMsg, IntPtr hWnd, uint wMsgFilterMin, uint wMsgFilterMax, uint wRemoveMsg);
        
        private const uint PM_REMOVE = 0x0001; // Messages should be removed from the queue
        
        static void Main()
        {
            Thread messageLoopThread = new Thread(() =>
            {
                while (true)
                {
                    
                    if (PeekMessage(out _, IntPtr.Zero, 0, 0, PM_REMOVE))
                    {

                    }
                    else
                    {
                        Thread.Sleep(Timeout.Infinite); 
                    }
                }
            });
            
            messageLoopThread.Start();

        }
    }
}