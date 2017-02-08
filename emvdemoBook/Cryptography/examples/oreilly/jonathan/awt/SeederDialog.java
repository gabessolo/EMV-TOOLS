package oreilly.jonathan.awt;

import java.awt.*;
import java.awt.event.*;

import oreilly.jonathan.util.*;

public class SeederDialog
    extends Dialog
    implements ActionListener, KeyListener {
  ProgressBar mProgressBar;
  Seeder mSeeder;

  public SeederDialog(Frame parent, int seedBytes) {
    super(parent, "Seeder Dialog", true);
    setupWindow(seedBytes);
  }

  public byte[] getSeed() { return mSeeder.getSeed(); }

  public void actionPerformed(ActionEvent ae) { dispose(); }

  public void keyPressed(KeyEvent ke) {}
  public void keyReleased(KeyEvent ke) {}
  public void keyTyped(KeyEvent ke) {
    mProgressBar.setLevel(mSeeder.getCurrentBitIndex());
  }

  protected void setupWindow(int seedBytes) {
    setFont(new Font("TimesRoman", Font.PLAIN, 12));
    setLayout(new GridLayout(4, 1));
    Label t1 = new Label("Please type some keys");
    Label t2 = new Label("to initialize the random");
    Label t3 = new Label("number generator.");
    add(t1);
    add(t2);
    add(t3);
    mProgressBar = new ProgressBar();
    Panel p = new Panel();
    p.add(mProgressBar);
    add(p);
    
    setSize(200, 200);
    setLocation(100, 100);
    pack();
  
    mSeeder = new Seeder(seedBytes);
    mProgressBar.setMaximum(mSeeder.getBitLength());
    mSeeder.addActionListener(this);
    
    t1.addKeyListener(mSeeder);
    t1.addKeyListener(this);
    t1.requestFocus();
  }
}