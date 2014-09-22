%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% Yi-Chao Chen
%% 2013.10.08 @ UT Austin
%%
%% - Input:
%%
%%
%% - Output:
%%
%%
%% e.g.
%%
%%     
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

function plot_cdf()
    addpath('../utils');

    %% --------------------
    %% DEBUG
    %% --------------------
    DEBUG0 = 0;
    DEBUG1 = 1;
    DEBUG2 = 1;


    %% --------------------
    %% Variable
    %% --------------------
    input_dir  = '../processed_data/subtask_dns/interval/';
    output_dir = '../processed_data/subtask_dns/interval/';
    fig_dir    = '../processed_data/subtask_dns/interval/figures/';

    tether_files = {'COMB13.txt', 'COMB14.txt', 'COMB34.txt', 'COMB16.txt', 'COMB36.txt'};
    non_tether_files = {'dns1.pcap.txt', 'dns3.pcap.txt', 'dns4.pcap.txt', 'dns6.pcap.txt'};

    % num_tether = length(tether_files);
    % num_non_tether = length(non_tether_files);
    % num_files = num_tether + num_non_tether;
    % xx = {1:num_files};
    % yy = {1:num_files};
    % legends = {1:num_files};

    cnt = 1;


    %% --------------------
    %% Check input
    %% --------------------

    %% --------------------
    %% Main starts
    %% --------------------

    %% --------------------
    %% non tethering file
    %% --------------------
    for fi = 1:length(non_tether_files)
        f = deblank(char(non_tether_files{fi}));
        fprintf('%s\n', f);

        data = load([input_dir f]);
        data = reshape(data, 1, []);

        [f,x] = ecdf(data);

        xx{cnt} = x;
        yy{cnt} = f;
        legends{cnt} = ['non-tether' int2str(fi)];
        cnt = cnt + 1;
    end

    %% --------------------
    %% tethering file
    %% --------------------
    for fi = 1:length(tether_files)
        f = deblank(char(tether_files{fi}));
        fprintf('%s\n', f);

        data = load([input_dir f]);
        data = reshape(data, 1, []);

        [f,x] = ecdf(data);

        xx{cnt} = x;
        yy{cnt} = f;
        legends{cnt} = ['tether' int2str(fi)];
        cnt = cnt + 1;
    end

    %% --------------------
    %% plot
    %% --------------------
    plot_my(xx, yy, legends, [fig_dir 'itvl.cdf'], 'interval (s)', 'CDF');

end



function plot_my(x, y, legends, file, x_label, y_label)

    colors  = {'r','b','g','c','m','y','k'};
    markers = {'+','o','*','.','x','s','d','^','>','<','p','h'};
    lines   = {'-','--',':','-.'};
    font_size = 18;
    cnt = 1;

    clf;
    fh = figure;
    hold all;

    lh = zeros(1, length(y));
    for yi = 1:length(y)
        xx = x{yi};
        yy = y{yi};

        %% line
        lh(yi) = plot(xx, yy);
        set(lh(yi), 'Color', char(colors(mod(cnt-1,length(colors))+1)));      %% color : r|g|b|c|m|y|k|w|[.49 1 .63]
        set(lh(yi), 'LineStyle', char(lines(mod(cnt-1,length(lines))+1)));
        set(lh(yi), 'LineWidth', 3);
        % if yi==1, set(lh(yi), 'LineWidth', 1); end
        % set(lh(yi), 'marker', char(markers(mod(cnt-1,length(markers))+1)));
        % set(lh(yi), 'MarkerEdgeColor', 'auto');
        % set(lh(yi), 'MarkerFaceColor', 'auto');
        % set(lh(yi), 'MarkerSize', 12);

        cnt = cnt + 1;
    end

    % set(gca, 'XTick', [0:20:140]);

    set(gca, 'FontSize', font_size);
    set(fh, 'PaperUnits', 'points');
    set(fh, 'PaperPosition', [0 0 1024 768]);
    set(gca, 'XLim', [0 400]);

    xlabel(x_label, 'FontSize', font_size);
    ylabel(y_label, 'FontSize', font_size);

    kh = legend(legends);
    % set(kh, 'Box', 'off');
    set(kh, 'Location', 'Best');
    % set(kh, 'Orientation', 'horizontal');
    % set(kh, 'Position', [.1,.2,.1,.2]);

    grid on;

    print(fh, '-dpng', [file '.png']);
end