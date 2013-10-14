/**************************************************
 * Author: Yi-Chao Chen
 * 2013/07/16 @ Narus
 *
 * Calculate the boot time using TCP Timestamp option and use Weka X-Means for clustering (using ELKI library)
 *
 * - input:
 *     ./output/
 *        file.group.txt:
 *        The boot time of all IPs
 *        <normalized tcp timestamp>
 *
 * - output
 *     a) ./output/
 *        file.<ip>.offset.txt:
 *        <tx_time> <rx_time> <rx_time_from_1st_pkt> <tx_clock_from_1st_pkt> <tx_time_from_1st_pkt> <offset>
 *     b) ./figures
 *
 * - internal variables
 *     a) PLOT_EPS : output eps or png figure
 *     c) gnuplot  : modify to choose which IPs to plot
 *
 *  e.g. java group_by_tcp_timestamp ./output/2013.07.08.ut.4machines.pcap.txt.group.txt
**************************************************/

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.util.ArrayList;
import java.util.List;
import java.util.Enumeration;

import de.lmu.ifi.dbs.elki.distance.distancefunction.minkowski.EuclideanDistanceFunction;
import de.lmu.ifi.dbs.elki.algorithm.clustering.DBSCAN;
import de.lmu.ifi.dbs.elki.algorithm.clustering.DBSCAN.Parameterizer;
import de.lmu.ifi.dbs.elki.distance.distancevalue.DoubleDistance;

public class group_by_tcp_timestamp_elki
{
    /************************
     * Variables
    *************************/
    /* DEBUG */
    private static boolean DEBUG0 = true;
    private static boolean DEBUG1 = false;
    private static boolean DEBUG2 = true;

    /* Constant */
    // private 


    /************************
     * main function
    *************************/
    public static void main(String[] args) throws Exception {

        /************************
         * Local variables
        *************************/
        String filename;
        double epsilon = 100;
        int minpts = 100;
        DBSCAN <double, DoubleDistance> dbscan = new DBSCAN(EuclideanDistanceFunction, epsilon, imnpts);
        

        // Check # of input
        if (args.length == 0) {
            System.err.println("\nUsage: java group_by_tcp_timestamp filename target_ip\n");
            System.exit(1);
        }
        filename  = args[0];
        

        // Read input file
        if(DEBUG2) {
            System.out.println("input file name: " + filename);
            System.out.println();
        }
        
        BufferedReader buf = new BufferedReader(new FileReader(filename));
        String line = null;
        while((line = buf.readLine()) != null) {
            String[] row = line.split(", ");
            double this_boot_time = Double.valueOf(row[0]).doubleValue();
            // boot_times.add_val(this_boot_time);

            if(DEBUG1) {
                System.out.println(this_boot_time);
            }
        }
        
    }   /* end main */

}

