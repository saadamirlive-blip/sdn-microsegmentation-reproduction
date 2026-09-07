"""Machine-learning pipeline: dataset build, preprocessing, RF train, RF evaluate.

Corresponds to the paper's "3-Phase Machine Learning and OpenFlow Deployment
Pipeline" (Sec III.D):
  Phase 1  -> ml/dataset_builder.py   (50,000-sample 6-D dataset)
  Phase 2  -> ml/preprocessing.py + ml/train_rf.py  (StandardScaler + RF)
  (Phase 3 -- runtime -- lives in controller/ and simulation/)
"""
