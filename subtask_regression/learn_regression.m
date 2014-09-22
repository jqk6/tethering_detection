%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%% Yi-Chao Chen
%% 2013.12.16 @ UT Austin
%%
%% - Input:
%%
%%
%% - Output:
%%
%%
%% e.g.
%%  [tp, tn, fp, fn, precision, recall, f1] = learn_regression('../processed_data/subtask_regression/results.sjtu.1.txt'); fprintf('%d, %d, %d, %d\n%f, %f, %f\n', tp, tn, fp, fn, precision, recall, f1)
%%     
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

function [tp, tn, fp, fn, precision, recall, f1] = learn_regression(fullpath)
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
    input_dir  = '';
    output_dir = '';


    %% --------------------
    %% Check input
    %% --------------------
    % if nargin < 1, arg = 1; end
    % if nargin < 1, arg = 1; end
    [filename, input_dir] = basename(fullpath);
    fprintf('input dir: %s\n', input_dir);
    fprintf('file name: %s\n', filename);


    %% --------------------
    %% Main starts
    %% --------------------

    %% --------------------
    %% read file
    %% --------------------
    if DEBUG2, fprintf('read file\n'); end

    data = load(fullpath);
    sx = size(data);


    %% --------------------
    %% regression
    %% --------------------
    coeffs = regress(data(:,1), data(:, 2:end))


    %% --------------------
    %% detection
    %% --------------------
    pred = data(:, 2:end) * coeffs;
    gt_non_tether_ix = find(data(:,1) == 0);
    gt_tether_ix     = find(data(:,1) == 1);

    pred_non_tether_ix = find(pred < 0.5);
    pred_tether_ix     = find(pred >= 0.5);

    tp = length(intersect(gt_tether_ix, pred_tether_ix));
    tn = length(intersect(gt_non_tether_ix, pred_non_tether_ix));
    fp = length(intersect(gt_non_tether_ix, pred_tether_ix));
    fn = length(intersect(gt_tether_ix, pred_non_tether_ix));

    precision = tp / (tp + fp);
    recall    = tp / (tp + fn);
    f1        = 2 * precision * recall / (precision + recall);

end
