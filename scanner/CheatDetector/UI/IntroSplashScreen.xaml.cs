using System.Windows;
using System.Windows.Threading;

namespace CheatDetector.UI;

public partial class IntroSplashScreen : Window
{
    private readonly DispatcherTimer _timer;

    public IntroSplashScreen()
    {
        InitializeComponent();

        _timer = new DispatcherTimer
        {
            Interval = TimeSpan.FromMilliseconds(1800)
        };
        _timer.Tick += (s, e) =>
        {
            _timer.Stop();
            DialogResult = true;
            Close();
        };
        _timer.Start();
    }
}
