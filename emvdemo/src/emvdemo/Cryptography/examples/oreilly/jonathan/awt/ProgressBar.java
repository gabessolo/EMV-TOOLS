package oreilly.jonathan.awt;

import java.awt.*;

public class ProgressBar
    extends Canvas {
  int mLevel;
  int mMaximum;
  Color mFrameColor;

  public ProgressBar() { this(100); }
  
  public ProgressBar(int max) {
    setForeground(Color.blue);
    mFrameColor = Color.black;
    setMaximum(max);
    setLevel(0);
  }

  public void setMaximum(int max) {
    mMaximum = max;
    repaint();
  }
	
  public void setLevel(int level) {
    mLevel = (level > mMaximum) ? mMaximum : level;
    repaint();
  }

  public void update(Graphics g) { paint(g); }
	
  public void paint(Graphics g) {
    Dimension d = getSize();
    double ratio = (double)((double)mLevel / (double)mMaximum);
    int x = (int)((double)d.width * ratio);

    g.setColor(mFrameColor);
    g.drawRect(0, 0, d.width - 1, d.height - 1);

    g.setColor(getForeground());
    g.fillRect(1, 1, x, d.height - 2);

    g.setColor(getBackground());
    g.fillRect(x + 1, 1, d.width - 2 - x, d.height - 2);
  }
	
  public Dimension getMinimumSize() { return new Dimension(10, 1); }
  public Dimension getPreferredSize() { return new Dimension(100, 10); }
}