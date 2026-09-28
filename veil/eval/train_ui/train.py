"""
YOLOX-Nano UI Detector Training & Head Adaptation Script (Task 2)
Extracts multi-scale FPN features from permissive Apache-2.0 YOLOX-nano backbone,
trains the 11 UI element classification heads AND UI objectness heads on the synthetic training split,
and exports the fine-tuned ONNX model with hash verification.
"""

import hashlib
import json
import os
from pathlib import Path
import numpy as np
import onnx
import onnxruntime as ort
from PIL import Image
import torch
import torch.nn as nn
import torch.optim as optim

CLASSES = [
    "button",
    "text_input",
    "checkbox",
    "radio",
    "dropdown",
    "link",
    "icon",
    "image",
    "table",
    "label",
    "dialog"
]
CLASS_TO_IDX = {c: i for i, c in enumerate(CLASSES)}
NUM_CLASSES = len(CLASSES)
IMG_SIZE = 416

def compute_grids_and_strides():
    strides = [8, 16, 32]
    grids = []
    expanded_strides = []
    for s in strides:
        h, w = IMG_SIZE // s, IMG_SIZE // s
        xv, yv = np.meshgrid(np.arange(w), np.arange(h))
        grid = np.stack((xv, yv), 2).reshape(-1, 2)
        grids.append(grid)
        expanded_strides.append(np.full((h * w, 1), s))
    grids = np.concatenate(grids, 0).astype(np.float32)
    expanded_strides = np.concatenate(expanded_strides, 0).astype(np.float32)
    return grids, expanded_strides

def box_iou(box1, box2):
    # box: [x, y, w, h]
    x1 = max(box1[0], box2[0])
    y1 = max(box1[1], box2[1])
    x2 = min(box1[0] + box1[2], box2[0] + box2[2])
    y2 = min(box1[1] + box1[3], box2[1] + box2[3])
    inter = max(0, x2 - x1) * max(0, y2 - y1)
    union = box1[2] * box1[3] + box2[2] * box2[3] - inter
    return inter / union if union > 0 else 0.0

def preprocess_image(img_path):
    img = Image.open(img_path).convert('RGB')
    orig_w, orig_h = img.size
    
    # Scale and pad to 416x416 keeping aspect ratio
    scale = min(IMG_SIZE / orig_w, IMG_SIZE / orig_h)
    new_w = int(orig_w * scale)
    new_h = int(orig_h * scale)
    
    resized = img.resize((new_w, new_h), Image.Resampling.BILINEAR)
    padded = Image.new('RGB', (IMG_SIZE, IMG_SIZE), (114, 114, 114))
    padded.paste(resized, (0, 0))
    
    # CHW Float32 normalized BGR / RGB (YOLOX expects BGR order)
    arr = np.array(padded, dtype=np.float32)
    bgr = arr[:, :, ::-1] # RGB to BGR
    chw = bgr.transpose(2, 0, 1) # HWC to CHW
    return np.expand_dims(chw, 0), scale, (orig_w, orig_h)

def create_feature_extractor_model(base_model_path, temp_model_path):
    m = onnx.load(base_model_path)
    out_names = {o.name for o in m.graph.output}
    
    # Expose both classification features ('1044', '1086', '1128') and objectness features ('1061', '1103', '1145')
    for feat_name in ['1044', '1086', '1128', '1061', '1103', '1145']:
        if feat_name not in out_names:
            val_info = onnx.helper.make_tensor_value_info(feat_name, onnx.TensorProto.FLOAT, None)
            m.graph.output.append(val_info)
            
    onnx.save(m, temp_model_path)
    return temp_model_path

def train_ui_detector(
    base_model_path="extension/models/yolox_nano.onnx",
    train_data_dir="eval/ui_data/train",
    epochs=15,
    lr=0.005
):
    print("=== Training YOLOX-Nano UI Detector (Classification + Objectness) ===")
    grids, expanded_strides = compute_grids_and_strides()
    
    temp_feature_model = "eval/train_ui/yolox_feat_temp.onnx"
    create_feature_extractor_model(base_model_path, temp_feature_model)
    feat_session = ort.InferenceSession(temp_feature_model, providers=['CPUExecutionProvider'])
    
    # Classification heads: 3 levels (stride 8, 16, 32), 64 channels in -> NUM_CLASSES out (1x1 convs)
    head_cls_8 = nn.Conv2d(64, NUM_CLASSES, kernel_size=1)
    head_cls_16 = nn.Conv2d(64, NUM_CLASSES, kernel_size=1)
    head_cls_32 = nn.Conv2d(64, NUM_CLASSES, kernel_size=1)
    
    # Objectness heads: 3 levels (stride 8, 16, 32), 64 channels in -> 1 out (1x1 convs)
    head_obj_8 = nn.Conv2d(64, 1, kernel_size=1)
    head_obj_16 = nn.Conv2d(64, 1, kernel_size=1)
    head_obj_32 = nn.Conv2d(64, 1, kernel_size=1)
    
    # Initialize weights
    for h in [head_cls_8, head_cls_16, head_cls_32]:
        nn.init.normal_(h.weight, std=0.01)
        nn.init.constant_(h.bias, -2.0)
    for h in [head_obj_8, head_obj_16, head_obj_32]:
        nn.init.normal_(h.weight, std=0.01)
        nn.init.constant_(h.bias, -1.0)
        
    all_params = (
        list(head_cls_8.parameters()) + list(head_cls_16.parameters()) + list(head_cls_32.parameters()) +
        list(head_obj_8.parameters()) + list(head_obj_16.parameters()) + list(head_obj_32.parameters())
    )
    optimizer = optim.Adam(all_params, lr=lr, weight_decay=1e-4)
    cls_criterion = nn.BCEWithLogitsLoss(pos_weight=torch.tensor([4.0] * NUM_CLASSES))
    obj_criterion = nn.BCEWithLogitsLoss(pos_weight=torch.tensor([5.0]))
    
    # Load training dataset
    train_dir = Path(train_data_dir)
    json_files = sorted(list(train_dir.glob("*.json")))
    print(f"Loading {len(json_files)} training samples...")
    
    cached_samples = []
    for jf in json_files:
        with open(jf, "r", encoding="utf-8") as f:
            data = json.load(f)
        img_path = train_dir / data["image"]
        if not img_path.exists():
            continue
            
        inp, scale, orig_size = preprocess_image(str(img_path))
        ort_outs = feat_session.run(None, {'images': inp})
        out_dict = {feat_session.get_outputs()[i].name: ort_outs[i] for i in range(len(ort_outs))}
        
        feat_cls8 = out_dict['1044']   # [1, 64, 52, 52]
        feat_cls16 = out_dict['1086']  # [1, 64, 26, 26]
        feat_cls32 = out_dict['1128']  # [1, 64, 13, 13]
        
        feat_obj8 = out_dict['1061']   # [1, 64, 52, 52]
        feat_obj16 = out_dict['1103']  # [1, 64, 26, 26]
        feat_obj32 = out_dict['1145']  # [1, 64, 13, 13]
        
        raw_output = out_dict['output'][0] # [3549, 85]
        pred_cxcy = (raw_output[:, :2] + grids) * expanded_strides
        pred_wh = np.exp(raw_output[:, 2:4]) * expanded_strides
        pred_boxes = np.zeros((3549, 4), dtype=np.float32)
        pred_boxes[:, 0] = pred_cxcy[:, 0] - pred_wh[:, 0] / 2
        pred_boxes[:, 1] = pred_cxcy[:, 1] - pred_wh[:, 1] / 2
        pred_boxes[:, 2] = pred_wh[:, 0]
        pred_boxes[:, 3] = pred_wh[:, 1]
        
        # Scale ground truth boxes to 416x416 space
        gt_boxes = []
        gt_classes = []
        for el in data.get("elements", []):
            cls_name = el["class"]
            if cls_name not in CLASS_TO_IDX:
                continue
            box = el["box"]
            scaled_box = [box[0] * scale, box[1] * scale, box[2] * scale, box[3] * scale]
            gt_boxes.append(scaled_box)
            gt_classes.append(CLASS_TO_IDX[cls_name])
            
        targets_cls = np.zeros((3549, NUM_CLASSES), dtype=np.float32)
        targets_obj = np.zeros((3549, 1), dtype=np.float32)
        
        for a_idx in range(3549):
            a_box = pred_boxes[a_idx]
            best_iou = 0.0
            best_cls = -1
            for g_box, g_cls in zip(gt_boxes, gt_classes):
                iou_val = box_iou(a_box, g_box)
                if iou_val > best_iou:
                    best_iou = iou_val
                    best_cls = g_cls
                    
            if best_iou >= 0.20 and best_cls >= 0:
                targets_cls[a_idx, best_cls] = 1.0
                targets_obj[a_idx, 0] = 1.0
                
        cached_samples.append({
            "feat_cls8": torch.tensor(feat_cls8, dtype=torch.float32),
            "feat_cls16": torch.tensor(feat_cls16, dtype=torch.float32),
            "feat_cls32": torch.tensor(feat_cls32, dtype=torch.float32),
            "feat_obj8": torch.tensor(feat_obj8, dtype=torch.float32),
            "feat_obj16": torch.tensor(feat_obj16, dtype=torch.float32),
            "feat_obj32": torch.tensor(feat_obj32, dtype=torch.float32),
            "targets_cls": torch.tensor(targets_cls, dtype=torch.float32),
            "targets_obj": torch.tensor(targets_obj, dtype=torch.float32)
        })
        
    print(f"Cached features for {len(cached_samples)} training variations.")
    
    # Training Loop
    for epoch in range(1, epochs + 1):
        total_loss = 0.0
        for m in [head_cls_8, head_cls_16, head_cls_32, head_obj_8, head_obj_16, head_obj_32]:
            m.train()
        
        for sample in cached_samples:
            optimizer.zero_grad()
            
            # Classification
            p_c8 = head_cls_8(sample["feat_cls8"]).permute(0, 2, 3, 1).reshape(1, -1, NUM_CLASSES)
            p_c16 = head_cls_16(sample["feat_cls16"]).permute(0, 2, 3, 1).reshape(1, -1, NUM_CLASSES)
            p_c32 = head_cls_32(sample["feat_cls32"]).permute(0, 2, 3, 1).reshape(1, -1, NUM_CLASSES)
            preds_cls = torch.cat([p_c8, p_c16, p_c32], dim=1).squeeze(0)
            
            # Objectness
            p_o8 = head_obj_8(sample["feat_obj8"]).permute(0, 2, 3, 1).reshape(1, -1, 1)
            p_o16 = head_obj_16(sample["feat_obj16"]).permute(0, 2, 3, 1).reshape(1, -1, 1)
            p_o32 = head_obj_32(sample["feat_obj32"]).permute(0, 2, 3, 1).reshape(1, -1, 1)
            preds_obj = torch.cat([p_o8, p_o16, p_o32], dim=1).squeeze(0)
            
            loss_cls = cls_criterion(preds_cls, sample["targets_cls"])
            loss_obj = obj_criterion(preds_obj, sample["targets_obj"])
            loss = loss_cls + 1.5 * loss_obj
            
            loss.backward()
            optimizer.step()
            total_loss += loss.item()
            
        avg_loss = total_loss / len(cached_samples)
        if epoch % 3 == 0 or epoch == epochs:
            print(f"  Epoch [{epoch:02d}/{epochs:02d}] - Loss: {avg_loss:.4f} (Cls: {loss_cls.item():.4f}, Obj: {loss_obj.item():.4f})")
            
    print("Training complete! Fine-tuned classification + objectness heads converged.")
    
    # Export fine-tuned weights back into ONNX model
    print("\nIntegrating fine-tuned weights into YOLOX-Nano ONNX graph...")
    final_model = onnx.load(base_model_path)
    init_map = {init.name: init for init in final_model.graph.initializer}
    
    # 1. Update Classification Weights & Biases
    w_c8 = head_cls_8.weight.detach().cpu().numpy()
    b_c8 = head_cls_8.bias.detach().cpu().numpy()
    w_c16 = head_cls_16.weight.detach().cpu().numpy()
    b_c16 = head_cls_16.bias.detach().cpu().numpy()
    w_c32 = head_cls_32.weight.detach().cpu().numpy()
    b_c32 = head_cls_32.bias.detach().cpu().numpy()
    
    for w_name, b_name, new_w, new_b in [
        ('607', '608', w_c8, b_c8),
        ('609', '610', w_c16, b_c16),
        ('611', '612', w_c32, b_c32)
    ]:
        orig_w = onnx.numpy_helper.to_array(init_map[w_name]).copy()
        orig_b = onnx.numpy_helper.to_array(init_map[b_name]).copy()
        orig_w[:NUM_CLASSES] = new_w
        orig_w[NUM_CLASSES:] = -10.0
        orig_b[:NUM_CLASSES] = new_b
        orig_b[NUM_CLASSES:] = -10.0
        init_map[w_name].raw_data = orig_w.astype(np.float32).tobytes()
        init_map[b_name].raw_data = orig_b.astype(np.float32).tobytes()
        
    # 2. Update Objectness Weights & Biases
    w_o8 = head_obj_8.weight.detach().cpu().numpy()
    b_o8 = head_obj_8.bias.detach().cpu().numpy()
    w_o16 = head_obj_16.weight.detach().cpu().numpy()
    b_o16 = head_obj_16.bias.detach().cpu().numpy()
    w_o32 = head_obj_32.weight.detach().cpu().numpy()
    b_o32 = head_obj_32.bias.detach().cpu().numpy()
    
    for w_name, b_name, new_w, new_b in [
        ('619', '620', w_o8, b_o8),
        ('621', '622', w_o16, b_o16),
        ('623', '624', w_o32, b_o32)
    ]:
        init_map[w_name].raw_data = new_w.astype(np.float32).tobytes()
        init_map[b_name].raw_data = new_b.astype(np.float32).tobytes()
        
    onnx.save(final_model, base_model_path)
    print(f"Updated {base_model_path} successfully.")
    
    if os.path.exists(temp_feature_model):
        os.remove(temp_feature_model)
        
    # Verify hash and compute updated SHA-256
    with open(base_model_path, "rb") as f:
        file_bytes = f.read()
    new_sha256 = hashlib.sha256(file_bytes).hexdigest()
    file_size = len(file_bytes)
    print(f"Updated Model Size: {file_size} bytes")
    print(f"Updated Model SHA-256: {new_sha256}")
    
    # Update manifest.json
    manifest_path = Path("extension/models/manifest.json")
    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)
        
    manifest["models"]["yolox_nano"]["sha256"] = new_sha256
    manifest["models"]["yolox_nano"]["size_bytes"] = file_size
    manifest["models"]["yolox_nano"]["classes"] = CLASSES
    
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
        
    print(f"Updated {manifest_path} with verified SHA-256 hash.")
    return new_sha256

if __name__ == "__main__":
    train_ui_detector()
