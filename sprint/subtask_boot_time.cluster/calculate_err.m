
%% calculate_err: function description
function [outputs] = calculate_err()
    %% DEBUG
    DEBUG0 = 1;
    DEBUG1 = 0;
    DEBUG2 = 1;


    %% Constant
    PLOT_1 = 0;
    PLOT_2 = 0;
    PLOT_3 = 1;

    figure_dir = './figures_simulation';
    time_gran = 0.1;
    time = [0:time_gran:1000];
    

    if PLOT_1 == 1
        % real_freq = [100, 128, 256, 900, 1000];
        real_freq = [256];
        estimated_freq_range = [0:0.2:1];
        boot_time = 0;
        error_ts = zeros(length(real_freq) * length(estimated_freq_range), size(time, 2));
        titles = cell(1, length(real_freq) * length(estimated_freq_range));
        cnt_series = 1;

        for this_real_freq = real_freq
            estimated_freq = this_real_freq + estimated_freq_range;

            for this_estimated_freq = estimated_freq
                this_title = sprintf('real f=%d, est f=%d', this_real_freq, this_estimated_freq);
                titles{cnt_series} = this_title;
                
                
                if DEBUG2 == 1
                    disp(this_title);
                end


                start_index = boot_time/time_gran + 1;
                if(start_index > 1) 
                    error_ts(cnt_series, 1:(start_index-1)) = 0;
                end
                error_ts(cnt_series, start_index:end) = abs((time(1, start_index:end) - boot_time) * (this_real_freq - this_estimated_freq));


                if DEBUG1 == 1
                    time(1, 1:10) - boot_time
                    this_real_freq - this_estimated_freq
                    error_ts(1, 1:10)
                end


                cnt_series = cnt_series + 1;
            end
        end

        fh1 = figure;
        plot(time, error_ts, 'LineWidth', 4);
        legend(titles, 'Location', 'NorthOutside');
        xlabel('time (s)');
        ylabel('error of estimated Timestamp');
        print([figure_dir '/self_error.pdf'],'-dpdf');
        close all;
    end %% end plot 1

    
    %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%


    if PLOT_2 == 1
        boot_time_1 = [100];
        % freq_1 = [100, 128, 256, 1000];
        freq_1 = [256];

        boot_time_2 = [0];
        freq_2 = [100, 128, 256, 1000];

        total_sim = length(boot_time_1) * length(freq_1) * length(boot_time_2) * length(freq_2);
        cnt_series = 1;
        error_ts = zeros(total_sim, size(time, 2));
        titles = cell(1, total_sim);
        cnt_series = 1;

        for this_boot_1 = boot_time_1
            for this_boot_2 = boot_time_2
                for this_freq_1 = freq_1
                    for this_freq_2 = freq_2
                        % this_title = sprintf('boot1=%d, freq1=%d, boot2=%d, freq2=%d', this_boot_1, this_freq_1, this_boot_2, this_freq_2);
                        this_title = sprintf('freq1=%d, freq2=%d', this_freq_1, this_freq_2);
                        titles{cnt_series} = this_title;


                        if DEBUG2 == 1
                            disp(this_title);
                        end

                        start_index = max(this_boot_1, this_boot_2) / time_gran + 1;
                        if(start_index > 1) 
                            error_ts(cnt_series, 1:(start_index-1)) = 0;
                        end
                        error_ts(cnt_series, start_index:end) = abs((time(1, start_index:end) - this_boot_1) * this_freq_1 - (time(1, start_index:end) - this_boot_2) * this_freq_2);

                        cnt_series = cnt_series + 1;
                    end
                end
            end
        end

        fh2 = figure;
        plot(time, error_ts, 'LineWidth', 4);
        legend(titles, 'Location', 'NorthOutside');
        xlabel('time (s)');
        ylabel('error of estimated Timestamp');
        print([figure_dir '/two_device_error.pdf'],'-dpdf');
        close all;
    end  %% end plot 2


    %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%


    if PLOT_3 == 1
        boot_time_1 = 10;
        freq_1 = 256;
        density_period_1 = [5, 30];
        sending_interval_1 = [0.01, 5];
        density_state_1 = 0;
        pkt_time_ts_1 = zeros(size(time));
        pkt_Timestamp_ts_1 = zeros(size(time));
        noise_mean_1 = 0;
        noise_stdev_1 = 0.3;


        boot_time_2 = 65;
        freq_2 = 400;
        density_period_2 = [5, 30];
        sending_interval_2 = [0.01, 5];
        density_state_2 = 0;
        pkt_time_ts_2 = zeros(size(time));
        pkt_Timestamp_ts_2 = zeros(size(time));
        noise_mean_2 = 0;
        noise_stdev_2 = 0.5;


        boot_time_3 = 185;
        freq_3 = 350;
        density_period_3 = [5, 30];
        sending_interval_3 = [0.01, 5];
        density_state_3 = 0;
        pkt_time_ts_3 = zeros(size(time));
        pkt_Timestamp_ts_3 = zeros(size(time));
        noise_mean_3 = 0;
        noise_stdev_3 = 0.2;

        titles = cell(1, 3);
        titles{1} = ['d1: freq=' int2str(freq_1) 'Hz'];
        titles{2} = ['d2: freq=' int2str(freq_2) 'Hz'];
        titles{3} = ['d3: freq=' int2str(freq_3) 'Hz'];

        ind = 1;
        for this_time = time
            if(this_time < boot_time_1)
                pkt_time_ts_1(1, ind) = 0;
                pkt_Timestamp_ts_1(1, ind) = 0;
                continue;
            end

            if(density_state_1 == 0)
                pkt_time_ts_1(1, ind) = this_time;
                pkt_Timestamp_ts_1(1, ind) = abs((this_time - boot_time_1 + random('Normal',noise_mean_1,noise_stdev_1,1,1) ) * freq_1);
            end

            ind = ind + 1;
        end

        ind = 1;
        for this_time = time
            if(this_time < boot_time_2)
                pkt_time_ts_2(1, ind) = 0;
                pkt_Timestamp_ts_2(1, ind) = 0;
                continue;
            end


            if(density_state_2 == 0)
                pkt_time_ts_2(1, ind) = this_time;
                pkt_Timestamp_ts_2(1, ind) = abs((this_time - boot_time_2 + random('Normal',noise_mean_2,noise_stdev_2,1,1) ) * freq_2);
            end

            ind = ind + 1;
        end

        ind = 1;
        for this_time = time
            if(this_time < boot_time_3)
                pkt_time_ts_3(1, ind) = 0;
                pkt_Timestamp_ts_3(1, ind) = 0;
                continue;
            end

            if(density_state_3 == 0)
                pkt_time_ts_3(1, ind) = this_time;
                pkt_Timestamp_ts_3(1, ind) = abs((this_time - boot_time_3 + random('Normal',noise_mean_3,noise_stdev_3,1,1) ) * freq_3);
            end

            ind = ind + 1;
        end

        fh3 = figure;
        plot(pkt_time_ts_1, pkt_Timestamp_ts_1, 'r.');
        hold on;
        plot(pkt_time_ts_2, pkt_Timestamp_ts_2, 'b*');
        hold on;
        plot(pkt_time_ts_3, pkt_Timestamp_ts_3, 'go');
        legend(titles, 'Location', 'NorthOutside');
        xlabel('time (s)');
        ylabel('Timestamp');
        print([figure_dir '/multiple_devices.pdf'],'-dpdf');
        print([figure_dir '/multiple_devices.jpeg'],'-djpeg');
        close all;



        working_time = [200:time_gran:400];
        working_time_ind = int16(working_time ./ time_gran + 1);

        % size(pkt_time_ts_1)
        % size(time)
        % size(working_time)
        % working_time_ind(1, 1)
        % working_time_ind(1, end)

        sub_pkt_time_ts_1 = pkt_time_ts_1(1, working_time_ind);
        sub_pkt_Timestamp_ts_1 = pkt_Timestamp_ts_1(1, working_time_ind);
        sub_pkt_time_ts_2 = pkt_time_ts_2(1, working_time_ind);
        sub_pkt_Timestamp_ts_2 = pkt_Timestamp_ts_2(1, working_time_ind);
        sub_pkt_time_ts_3 = pkt_time_ts_3(1, working_time_ind);
        sub_pkt_Timestamp_ts_3 = pkt_Timestamp_ts_3(1, working_time_ind);


        pkt_boot_time_1 = zeros(size(working_time));
        pkt_boot_time_2 = zeros(size(working_time));
        pkt_boot_time_3 = zeros(size(working_time));
        for this_freq = 1:50:1000
            ind_1 = find(sub_pkt_Timestamp_ts_1 ~= 0);
            pkt_boot_time_1(1, ind_1) = sub_pkt_time_ts_1(1, ind_1) - sub_pkt_Timestamp_ts_1(1, ind_1) / this_freq;

            ind_2 = find(sub_pkt_Timestamp_ts_2 ~= 0);
            pkt_boot_time_2(1, ind_2) = sub_pkt_time_ts_2(1, ind_2) - sub_pkt_Timestamp_ts_2(1, ind_2) / this_freq;

            ind_3 = find(sub_pkt_Timestamp_ts_3 ~= 0);
            pkt_boot_time_3(1, ind_3) = sub_pkt_time_ts_3(1, ind_3) - sub_pkt_Timestamp_ts_3(1, ind_3) / this_freq;

            fh4 = figure;
            plot(pkt_boot_time_1(1, ind_1), zeros(size(pkt_boot_time_1(1, ind_1))), 'r.', 'MarkerSize', 13);
            hold on;
            plot(pkt_boot_time_2(1, ind_2), zeros(size(pkt_boot_time_2(1, ind_2))), 'b*', 'MarkerSize', 7);
            hold on;
            plot(pkt_boot_time_3(1, ind_3), zeros(size(pkt_boot_time_3(1, ind_3))), 'go', 'MarkerSize', 3)
            xlabel('time (s)');
            ylabel('Timestamp');
            legend(titles, 'Location', 'NorthOutside');
            print([figure_dir '/multiple_devices_' int2str(this_freq) '.pdf'],'-dpdf');
            print([figure_dir '/multiple_devices_' int2str(this_freq) '.jpeg'],'-djpeg');
            close all;
        end


        pkt_boot_time_1 = zeros(size(working_time));
        pkt_boot_time_2 = zeros(size(working_time));
        titles2 = cell(1, 2);
        titles2{1} = ['d1: freq=' int2str(freq_1) 'Hz'];
        titles2{2} = ['d2: freq=' int2str(freq_2) 'Hz'];

        for this_freq = 1:50:1000
            ind_1 = find(sub_pkt_Timestamp_ts_1 ~= 0);
            pkt_boot_time_1(1, ind_1) = sub_pkt_time_ts_1(1, ind_1) - sub_pkt_Timestamp_ts_1(1, ind_1) / this_freq;

            ind_2 = find(sub_pkt_Timestamp_ts_2 ~= 0);
            pkt_boot_time_2(1, ind_2) = sub_pkt_time_ts_2(1, ind_2) - sub_pkt_Timestamp_ts_2(1, ind_2) / this_freq;

            fh5 = figure;
            plot(pkt_boot_time_1(1, ind_1), zeros(size(pkt_boot_time_1(1, ind_1))), 'r.', 'MarkerSize', 13);
            hold on;
            plot(pkt_boot_time_2(1, ind_2), zeros(size(pkt_boot_time_2(1, ind_2))), 'b*', 'MarkerSize', 7);
            xlabel('time (s)');
            ylabel('Timestamp');
            legend(titles2, 'Location', 'NorthOutside');
            print([figure_dir '/multiple_devices_12_' int2str(this_freq) '.pdf'],'-dpdf');
            print([figure_dir '/multiple_devices_12_' int2str(this_freq) '.jpeg'],'-djpeg');
            close all;
        end






        %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
        pkt_boot_time_1 = zeros(size(working_time));
        pkt_boot_time_2 = zeros(size(working_time));
        pkt_boot_time_3 = zeros(size(working_time));
        ind_1 = find(sub_pkt_Timestamp_ts_1 ~= 0);
        pkt_boot_time_1(1, ind_1) = sub_pkt_time_ts_1(1, ind_1) - sub_pkt_Timestamp_ts_1(1, ind_1) / freq_1;

        ind_2 = find(sub_pkt_Timestamp_ts_2 ~= 0);
        pkt_boot_time_2(1, ind_2) = sub_pkt_time_ts_2(1, ind_2) - sub_pkt_Timestamp_ts_2(1, ind_2) / freq_2;

        ind_3 = find(sub_pkt_Timestamp_ts_3 ~= 0);
        pkt_boot_time_3(1, ind_3) = sub_pkt_time_ts_3(1, ind_3) - sub_pkt_Timestamp_ts_3(1, ind_3) / freq_3;

        fh6 = figure;
        plot(pkt_boot_time_1(1, ind_1), zeros(size(pkt_boot_time_1(1, ind_1))), 'r.', 'MarkerSize', 13);
        hold on;
        plot(pkt_boot_time_2(1, ind_2), zeros(size(pkt_boot_time_2(1, ind_2))), 'b*', 'MarkerSize', 7);
        hold on;
        plot(pkt_boot_time_3(1, ind_3), zeros(size(pkt_boot_time_3(1, ind_3))), 'go');
        xlabel('time (s)');
        ylabel('Timestamp');
        legend(titles, 'Location', 'NorthOutside');
        print([figure_dir '/multiple_devices_correct.pdf'],'-dpdf');
        print([figure_dir '/multiple_devices_correct.jpeg'],'-djpeg');
        close all;
        % fh4 = figure;
        % plot(pkt_boot_time_f1_1, zeros(size(pkt_boot_time_f1_1)), 'r.', 'MarkerSize', 10);
        % % plot(pkt_time_ts_1, pkt_boot_time_f1_1, 'r.', 'MarkerSize', 10);
        % hold on;
        % plot(pkt_boot_time_f1_2, zeros(size(pkt_boot_time_f1_2)), 'b.');
        % % plot(pkt_time_ts_2, pkt_boot_time_f1_2, 'b.');
        % % legend(titles, 'Location', 'NorthOutside');
        % xlabel('time (s)');
        % ylabel('Timestamp');
        % print([figure_dir '/multiple_devices_f1.pdf'],'-dpdf');
        % close all;

        % fh5 = figure;
        % plot(pkt_boot_time_f2_1, zeros(size(pkt_boot_time_f2_1)), 'r.');
        % % plot(pkt_time_ts_1, pkt_boot_time_f2_1, 'r.');
        % hold on;
        % plot(pkt_boot_time_f2_2, zeros(size(pkt_boot_time_f2_2)), 'b.', 'MarkerSize', 10);
        % % plot(pkt_time_ts_2, pkt_boot_time_f2_2, 'b.', 'MarkerSize', 10);
        % % legend(titles, 'Location', 'NorthOutside');
        % xlabel('time (s)');
        % ylabel('Timestamp');
        % print([figure_dir '/multiple_devices_f2.pdf'],'-dpdf');
        % close all;
    end  %% end plot 3

