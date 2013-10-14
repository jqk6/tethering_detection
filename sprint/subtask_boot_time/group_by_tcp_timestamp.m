%% -----------------------------------------------
% Author: Yi-Chao Chen
% 2013/07/08 @ Narus
%
% After calculate the normalized TCP Timestamp by "group_by_tcp_timestamp.pl", use classification toolbox to classify devices by normalized timestamps
%
% - input: parsed_pcap_text
%     ./output/
%     a) file.group.txt:
%        <normalized tcp timestamp>
%
%  e.g.
%      group_by_tcp_timestamp('2013.07.08.ut.4machines.pcap.txt.group.txt')
%% -----------------------------------------------

function[] = group_by_tcp_timestamp(file_name)

	addpath '~/bin/FUZZCLUST';

	min_group = 2;
	max_group = 20;

	input_dir = './output/';
	figures_dir = './figures_classification/';
	
	m = load([input_dir file_name]);
	size(m)


	PCs = zeros(max_group - min_group + 1);
	CEs = zeros(max_group - min_group + 1);
	SCs = zeros(max_group - min_group + 1);
	Ss = zeros(max_group - min_group + 1);
	XBs = zeros(max_group - min_group + 1);
	DIs = zeros(max_group - min_group + 1);
	ADIs = zeros(max_group - min_group + 1);

	for k = [min_group:max_group]
		fprintf('\nk=%d\n', k);
		
		%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
		%% k-means
		%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
		data.X = m(:, 1);
		%data normalization
		data = clust_normalize(data,'range');
		%parameters
		param.c = k;
		param.vis = 0;
		%clustering
		result = Kmeans2(data, param);
		%validation
		for val = [1:3]
			param.val = val;
			result = validity(result, data, param);
			% result.validity
		end
		fprintf('%f, %f, %f, %f, %f, %f, %f\n', result.validity.PC, result.validity.CE,  ...
			result.validity.SC, result.validity.S, result.validity.XB, ...
			result.validity.DI, result.validity.ADI);
		PCs(k-min_group+1) = result.validity.PC;
		CEs(k-min_group+1) = result.validity.CE;
		SCs(k-min_group+1) = result.validity.SC;
		Ss(k-min_group+1)  = result.validity.S;
		XBs(k-min_group+1) = result.validity.XB;
		DIs(k-min_group+1) = result.validity.DI;
		ADIs(k-min_group+1)= result.validity.ADI;
		% result.data.f
		% result.data.d
		% return
		
	end

	figure('visible','off')
	plot(SCs)
	print([figures_dir 'kmeans.' file_name '.SC.jpeg'],'-djpeg');
	plot(Ss)
	print([figures_dir 'kmeans.' file_name '.S.jpeg'],'-djpeg');
	plot(XBs)
	print([figures_dir 'kmeans.' file_name '.XB.jpeg'],'-djpeg');
	plot(DIs)
	print([figures_dir 'kmeans.' file_name '.DI.jpeg'],'-djpeg');
	plot(ADIs)
	print([figures_dir 'kmeans.' file_name '.ADI.jpeg'],'-djpeg');
	plot(PCs)
	print([figures_dir 'kmeans.' file_name '.PC.jpeg'],'-djpeg');
	plot(CEs)
	print([figures_dir 'kmeans.' file_name '.CE.jpeg'],'-djpeg');

	figure('visible','off')
	plot(DIs)
	hold on
	plot(ADIs)
	hold on
	plot(SCs)
	hold on
	plot(Ss)
	hold on
	% print([OutDir 'kmeans.lv'  int2str(level) '.' time_type '.' int2str(start_id) '.' int2str(end_id) 'decide_k.jpeg'],'-djpeg');


	close all;

end