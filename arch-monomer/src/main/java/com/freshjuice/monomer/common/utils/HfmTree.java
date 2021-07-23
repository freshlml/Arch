package com.freshjuice.monomer.common.utils;

public class HfmTree {


    private Node[] tree;
    private int length;
    public HfmTree(){tree=null;}
    public HfmTree(int[] weights, boolean sorted) {
        if(_init(weights)) {
            if(sorted) {buildTreeSelected();} else {buildTree();}
        }
    }

    private boolean _init(int[] weights) {
        if(weights == null) return false;
        length = weights.length;
        if(length == 0 || (2 * length - 1) > Integer.MAX_VALUE) {length=0; return false;}
        //weigths.value > 0
        tree = new Node[2 * length - 1];
        //初始化权重节点
        for(int i=0; i<length; i++) {
            tree[i] = new Node(weights[i], -1, -1, -1);
        }
        //初始化其他节点
        for(int i=length; i<tree.length; i++) {
            tree[i] = new Node(0, -1, -1, -1);
        }
        if(length == 1) return false;
        return true;
    }

    private void buildTreeSelected() {

        for(int i=length, pos=0; i<tree.length; i++) {

            for(int j=pos; j<pos+2; j++) {
                int mw = tree[j].weight;
                int mp = j;
                int k=j+1;
                for(; k<i; k++) {
                    if(mw > tree[k].weight) {mw = tree[k].weight; mp = k;}
                }
                if(mp != j) {
                    Node t = tree[j];
                    tree[j] = tree[mp];
                    tree[mp] = t;
                    //j 和 mp 如果有left right 的话，进行指针修正
                    if(tree[j].left != -1) {tree[tree[j].left].parent = j;}
                    if(tree[j].right != -1) {tree[tree[j].right].parent = j;}

                    if(tree[mp].left != -1) {tree[tree[mp].left].parent = mp;}
                    if(tree[mp].right != -1) {tree[tree[mp].right].parent = mp;}
                }
            }
            tree[pos].parent = i;
            tree[pos + 1].parent = i;
            tree[i].left = pos;
            tree[i].right = pos + 1;
            tree[i].weight = tree[pos].weight + tree[pos + 1].weight;

            pos += 2;
        }


    }

    private void buildTree() {
        for(int i=0; i<length-1; i++) {

            int start = length + i;

            int s1 = select(start, -1);
            int s2 = select(start, s1);
            tree[s1].parent = start;
            tree[s2].parent = start;
            tree[start].left = s1;
            tree[start].right = s2;
            tree[start].weight = tree[s1].weight + tree[s2].weight;

        }

    }

    private int select(int end, int s) {
        int l = -1;
        int s1 = -1;
        for(int i=0; i<end; i++) {
            if(s != i && l == -1 && tree[i].parent == -1) {l = tree[i].weight; s1=i; continue;}
            if(s != i && l > tree[i].weight && tree[i].parent == -1) {l = tree[i].weight; s1=i;}
        }
        return s1;
    }



    static class Node {
        int weight;
        int parent,left,right;

        public Node(int weight, int parent, int left, int right) {
            this.weight = weight;
            this.parent = parent;
            this.left = left;
            this.right = right;
        }

        public int getWeight() {
            return weight;
        }
        public void setWeight(int weight) {
            this.weight = weight;
        }
        public int getParent() {
            return parent;
        }
        public void setParent(int parent) {
            this.parent = parent;
        }
        public int getLeft() {
            return left;
        }
        public void setLeft(int left) {
            this.left = left;
        }
        public int getRight() {
            return right;
        }
        public void setRight(int right) {
            this.right = right;
        }
    }

}
