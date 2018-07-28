/*******************************************************************************
 * Copyright 2017 McGill University All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/
// Decompiled by Jad v1.5.8e. Copyright 2001 Pavel Kouznetsov.
// Jad home page: http://www.geocities.com/kpdus/jad.html
// Decompiler options: packimports(3) 
// Source File Name:   ReadList.java

package ca.mcgill.sis.dmas.kam1n0.cli.evaluator;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.NoSuchElementException;
import java.util.StringTokenizer;

// Referenced classes of package auc:
//            ClassSort, Confusion, PNPoint, AUCCalculator

public class ROCReadList
{

    public ROCReadList()
    {
    }

    public static ROCClassSort[] convertList(LinkedList<ROCClassSort> linkedlist)
    {
        ROCClassSort aclasssort[] = new ROCClassSort[linkedlist.size()];
        for(int i = 0; i < aclasssort.length; i++)
            aclasssort[i] = linkedlist.removeFirst();

        Arrays.sort(aclasssort);
        return aclasssort;
    }

    public static ROCConfusion accuracyScoreAllSplits(ROCClassSort aclasssort[], int i, int j)
    {
        Arrays.sort(aclasssort);
        for(int k = aclasssort.length - 1; k >= aclasssort.length - 20; k--);
        ROCConfusion confusion = new ROCConfusion(i, j);
        double d = aclasssort[aclasssort.length - 1].getProb();
        int i1 = aclasssort[aclasssort.length - 1].getClassification();
        double ad[] = new double[aclasssort.length];
        int ai1[] = new int[aclasssort.length];
        for(int k1 = 0; k1 < aclasssort.length; k1++)
        {
            ad[k1] = aclasssort[k1].getProb();
            ai1[k1] = aclasssort[k1].getClassification();
        }
        for(int l1 = aclasssort.length - 2; l1 >= 0; l1--)
        {
            int j1 = aclasssort[l1].getClassification();
            double d1 = aclasssort[l1].getProb();
            if(i1 == 1 && 0 == j1)
            {
                if(aclasssort[l1 + 1].getProb() <= d1 && aclasssort[l1 + 1].getProb() <= d1)
                    System.out.println("Bad");
                int ai[] = fastAccuracy(ad, ai1, d);
                confusion.addPoint(ai[0], ai[1]);
            }
            d = d1;
            i1 = j1;
        }

        return confusion;
    }

    public static int[] fastAccuracy(double ad[], int ai[], double d)
    {
        int ai1[] = new int[4];
        for(int i = 0; i < ai1.length; i++)
            ai1[i] = 0;

        for(int j = 0; j < ad.length; j++)
        {
            if(ad[j] >= d)
            {
                if(ai[j] == 1)
                    ai1[0]++;
                else
                    ai1[1]++;
                continue;
            }
            if(ai[j] == 1)
                ai1[2]++;
            else
                ai1[3]++;
        }

        return ai1;
    }

    public static ROCConfusion readFile(String s, String s1)
    {
        int i = 0;
        int j = 0;
        LinkedList<ROCClassSort> linkedlist = new LinkedList<ROCClassSort>();
        try
        {
            for(BufferedReader bufferedreader = new BufferedReader(new FileReader(new File(s))); bufferedreader.ready();)
            {
                String s2 = bufferedreader.readLine();
                StringTokenizer stringtokenizer = new StringTokenizer(s2, "\t ,");
                try
                {
                    double d = Double.parseDouble(stringtokenizer.nextToken());
                    int l = Integer.parseInt(stringtokenizer.nextToken());
                    linkedlist.add(new ROCClassSort(d, l));
                }
                catch(NumberFormatException numberformatexception)
                {
                    System.err.println("...skipping bad input line (bad numbers)");
                }
                catch(NoSuchElementException nosuchelementexception1)
                {
                    System.err.println("...skipping bad input line (missing data)");
                }
            }

        }
        catch(FileNotFoundException filenotfoundexception)
        {
            System.err.println((new StringBuilder()).append("ERROR: File ").append(s).append(" not found - exiting...").toString());
            System.exit(-1);
        }
        catch(NoSuchElementException nosuchelementexception)
        {
            System.err.println("...incorrect fileType argument, either PR or ROC - exiting");
            System.exit(-1);
        }
        catch(IOException ioexception)
        {
            System.err.println((new StringBuilder()).append("ERROR: IO Exception in file ").append(s).append(" - exiting...").toString());
            System.exit(-1);
        }
        ROCClassSort aclasssort[] = convertList(linkedlist);
        ArrayList<ROCPNPoint> arraylist = new ArrayList<ROCPNPoint>();
        double d1 = aclasssort[aclasssort.length - 1].getProb();
        if(aclasssort[aclasssort.length - 1].getClassification() == 1)
            i++;
        else
            j++;
        for(int i1 = aclasssort.length - 2; i1 >= 0; i1--)
        {
            double d2 = aclasssort[i1].getProb();
            int j1 = aclasssort[i1].getClassification();
            if(d2 != d1)
                arraylist.add(new ROCPNPoint(i, j));
            d1 = d2;
            if(j1 == 1)
                i++;
            else
                j++;
        }

        arraylist.add(new ROCPNPoint(i, j));
        ROCConfusion confusion = new ROCConfusion(i, j);
        ROCPNPoint pnpoint;
        for(Iterator<ROCPNPoint> iterator = arraylist.iterator(); iterator.hasNext(); confusion.addPoint(pnpoint.getPos(), pnpoint.getNeg()))
            pnpoint = iterator.next();

        confusion.sort();
        confusion.interpolate();
        return confusion;
    }

    public static final int TP = 0;
    public static final int FP = 1;
    public static final int FN = 2;
    public static final int TN = 3;
}
