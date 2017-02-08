package oreilly.jonathan.util;

public class Counter
    implements Runnable {
  protected boolean mTrucking;
  protected int mCounter;
  
  public Counter() {
    mTrucking = true;
    mCounter = 0;
    Thread t = new Thread(this);
    t.start();
  }
  
  public void run() {
    while (mTrucking)
      mCounter++;
  }
  
  public void stop() { mTrucking = false; }
  public int getCount() { return mCounter; }
}