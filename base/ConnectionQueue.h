#pragma once

#include "muduo/net/Callbacks.h"
#include "muduo/net/TcpConnection.h"
#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <stdexcept>
#include <string_view>
#include <sys/types.h>
#include <utility>

template <typename KeyType, typename ValueType, typename Hash = std::hash<KeyType>>
class HashMap {  // copyable, movable
public:
    using size_type = std::size_t;
    using DataType = std::pair<const KeyType*, ValueType*>;
    using KV_Pair = std::pair<const KeyType&, ValueType&>;

    template <typename value_type, typename data_type>
    class __hashmap_iterator {
    public:
        using reference = value_type&;
        using pointer = std::shared_ptr<value_type>;

        __hashmap_iterator(size_type idx, data_type *data, size_type size) : 
            idx_(idx),
            data_(data),
            size_(size)
        {
            
        }
        pointer operator->() const 
        { 
            return std::make_shared<value_type>(*data_[idx_].first, *data_[idx_].second); 
        }
        reference operator*() const
        {
            return *operator->();
        }
        __hashmap_iterator operator++()  // pre
        {
            while (++idx_ < size_) {
                if (data_[idx_].first != nullptr)
                    break;
            }
            return *this;
        }
        __hashmap_iterator operator++(int)  // post
        {
            auto tmp = *this;
            ++*this;
            return tmp;
        }
        __hashmap_iterator operator--()  // pre
        {
            while (--idx_ >= 0) {
                if (data_[idx_].first != nullptr)
                    break;
            }
            return *this;
        }
        __hashmap_iterator operator--(int)  // post
        {
            auto tmp = *this;
            --*this;
            return tmp;
        }
        bool operator==(const __hashmap_iterator &rhs) const
        {
            return rhs.idx_ == idx_ && rhs.data_ == data_;
        }
        bool operator!=(const __hashmap_iterator &rhs) const
        {
            return !operator==(rhs);
        }
        size_type idx_;
    private:
        data_type *data_;
        size_type size_;
    };
    using iterator = __hashmap_iterator<KV_Pair, DataType>;
    using const_iterator = __hashmap_iterator<const KV_Pair, const DataType>;

    explicit HashMap(size_type max_size) : 
        data_(new DataType[max_size]),
        size_(0),
        maxSize_(max_size),
        hash_()
    {
        for (size_type i = 0; i < maxSize_; ++i) {
            data_[i].first = nullptr;
            data_[i].second = nullptr;
        }
    }
    ~HashMap() 
    {
        for (size_type i = 0; i < maxSize_; ++i) {
            if (!data_[i].first) continue;
            // FIXME: data_[i] is array
            delete data_[i].first;
            delete data_[i].second;
        }
        delete [] data_;
    }
    HashMap(const HashMap &foo) : 
        data_(new DataType[foo.maxSize_]),
        size_(foo.size_),
        maxSize_(foo.maxSize_),
        hash_(foo.hash_)
    {
        for (size_type i = 0; i < maxSize_; ++i) {
            data_[i] == foo.data_[i];
            if (!data_[i]) continue;
            data_[i] = new KeyType(*foo.data_[i].first);
            data_[i] = new ValueType(*foo.data_[i].second);
        }
    }
    HashMap(HashMap &&foo) noexcept :
        data_(nullptr),
        size_(foo.size_),
        maxSize_(foo.maxSize_),
        hash_(std::move(foo.hash_))
    {
        std::swap(data_, foo.data_);
    }
    HashMap &operator=(HashMap rhs) 
    {
        swap(rhs);
        return *this;
    }
    void swap(HashMap<KeyType, ValueType, Hash> &rhs) noexcept
    {
        std::swap(data_, rhs.data_);
        std::swap(size_, rhs.size_);
        std::swap(maxSize_, rhs.maxSize_);
    }

    size_type size() const { return size_; }
    size_type maxSize() const { return maxSize_; }
    bool empty() const { return size_ == 0; }
    bool full() const { return size_ == maxSize_; }

    iterator begin()
    {
        size_type i = 0;
        for (i = 0; i < maxSize_; ++i) {
            if (data_[i].first) break;
        }
        return { i, data_, maxSize_ };
    }
    iterator end()
    {
        return { maxSize_, data_, maxSize_ };
    }
    const_iterator begin() const 
    {
        size_type i = 0;
        for (i = 0; i < maxSize_; ++i) {
            if (data_[i].first) break;
        }
        return { i, data_, maxSize_ };
    }
    const_iterator end() const
    {
        return { maxSize_, data_, maxSize_ };
    }
    const_iterator cbegin() const
    {
        size_type i = 0;
        for (i = 0; i < maxSize_; ++i) {
            if (data_[i].first) break;
        }
        return { i, data_, maxSize_ };
    }
    const_iterator cend() const
    {
        return { maxSize_, data_, maxSize_ };
    }

    iterator find(const KeyType &key)
    {
        auto i = findIdx(key);
        if (i == maxSize_ || !data_[i].first) return end();
        return { i, data_, maxSize_ };
    }
    ValueType &at(const KeyType &key)
    {
        auto it = find(key);
        if (it == end()) {
            throw std::out_of_range("HashMap::at " + key);
        }
        return it->second;
    }
    ValueType &operator[](const KeyType &key)
    {
        auto it = find(key);  // once search
        if (it == end()) {
            if (full()) throw std::out_of_range("queue is full");
            auto p = insert({key, ValueType()});  // FIXME: twice search
            assert(p.second);
            return p.first->second;
        }
        return it->second;
    }

    size_type count(const KeyType &key) const
    {
        size_type res = 0;
        for (auto it = begin(); it != end(); ++it) {
            if (it->first == key) ++res;
        }
        return res;
    }

    std::pair<iterator, bool> insert(const std::pair<KeyType, ValueType> &pair)  // FIXME: &&pair
    {
        if (full()) return { end(), false };
        auto i = findIdx(pair.first);
        if (data_[i].first) return { iterator(i, data_, maxSize_), false };  // refer to element existed
        data_[i].first = new KeyType(pair.first);
        data_[i].second = new ValueType(pair.second);
        ++size_;
        return { iterator(i, data_, maxSize_), true };
    }

    size_type erase(const KeyType& key)
    {
        auto i = findIdx(key);
        if (i == maxSize_ || !data_[i].first) return 0;
        delete data_[i].first;
        delete data_[i].second;
        data_[i].first = nullptr;
        data_[i].second = nullptr;
        --size_;
        return 1;
    }
    iterator erase(const_iterator pos)
    {
        delete data_[pos.idx_].first;
        delete data_[pos.idx_].second;
        data_[pos.idx_].first = nullptr;
        data_[pos.idx_].first = nullptr;
        --size_;
        return iterator((++pos).idx_);
    }
    iterator erase(iterator pos)
    {
        delete data_[pos.idx_].first;
        delete data_[pos.idx_].second;
        data_[pos.idx_].first = nullptr;
        data_[pos.idx_].first = nullptr;
        --size_;
        return ++pos;
    }

private:
    // find the placement of a key
    // return a new placement for a key if not found
    // return maxSize_ if no space for a new key
    size_type findIdx(const KeyType &key)
    {
        size_type h = hash_(key) % maxSize_;
        size_type first_null = maxSize_;
        if (data_[h].first && *data_[h].first == key) {
            return h;
        } else if (!data_[h].first && first_null == maxSize_) {
            first_null = h;
        }
        // std::cout << "collision at " << key << " " << h << std::endl;
        // TODO: square find
        for (size_type nh = (h + 1) % maxSize_; nh != h; nh = (nh + 1) % maxSize_) {
            if (data_[nh].first && *data_[nh].first == key) {
                return nh;
            }  else if (!data_[nh].first && first_null == maxSize_) {
                first_null = nh;
            }
        }
        return first_null;
    }
    DataType *data_;
    size_type size_;
    size_type maxSize_;
    const Hash hash_;
};


template <typename T>
class CircularQueue {  // movable, copyable
    static_assert(std::is_scalar<T>::value, "T must be a scalar type");
public:
    using iterator = T*;
    using const_iterator = const T*;
    using size_type = std::size_t;

    explicit CircularQueue(size_type max_size) :
        capacity_(max_size + 1),
        maxSize_(max_size),
        data_(new T[capacity_]),
        begin_(data_),
        end_(data_)
    {
        // std::cout << "ctor " << this << std::endl;
    }
    ~CircularQueue()
    {
        // std::cout << "dtor " << this << std::endl;
        delete [] data_;
    }
    CircularQueue(CircularQueue &&rhs) :
        data_(nullptr),
        begin_(),
        end_()
    {
        // std::cout << "move ctor " << this << " from " << &rhs << std::endl;
        swap(rhs);
    }
    CircularQueue(const CircularQueue &rhs) :
        capacity_(rhs.capacity_),
        maxSize_(rhs.maxSize_),
        data_(new T[capacity_]),
        begin_(rhs.begin_ - rhs.data_ + data_),
        end_(rhs.end_ - rhs.data_ + data_)
    {
        // std::cout << "copy ctor " << this << " from " << &rhs << std::endl;
        std::copy(rhs.data_, rhs.data_ + capacity_, data_);
    }
    CircularQueue &operator=(const CircularQueue &rhs)
    {
        // std::cout << "=copy " << &rhs << " to " << this << std::endl;
        auto t = CircularQueue<T>(rhs);
        swap(t);
        return *this;
    }
    CircularQueue &operator=(CircularQueue &&rhs)
    {
        // std::cout << "=move " << &rhs << " to " << this << std::endl;
        swap(rhs);
        return *this;
    }
    void swap(CircularQueue &rhs) noexcept
    {
        std::swap(capacity_, rhs.capacity_);
        std::swap(maxSize_, rhs.maxSize_);
        std::swap(data_, rhs.data_);
        std::swap(begin_, rhs.begin_);
        std::swap(end_, rhs.end_);
    }

    T &front() { return *begin_; }
    T &back() { return data_[(end_  - data_ - 1 + capacity_) % capacity_]; }
    const T &front() const { return *begin_; }
    const T &back() const { return data_[(end_  - data_ - 1 + capacity_) % capacity_]; }

    bool full() const { return size() == maxSize_; }
    bool empty() const { return end_ == begin_; }
    size_type size() const { return (end_ - begin_ + capacity_) % capacity_; }
    size_type maxSize() const { return maxSize_; }
    
    void push(T e)
    {
        if (size() == maxSize_) {
            throw std::out_of_range("queue is full");
        }
        *end_ = e;
        end_ = (end_ - data_ + 1) % capacity_ + data_;
    }
    void pop()
    {
        if (empty()) {
            throw std::out_of_range("queue is empty");
        }
        begin_ = (begin_ - data_ + 1) % capacity_ + data_;
    }
    void assign(std::initializer_list<T> ilist)
    {
        end_ = std::copy(ilist.begin(), ilist.end(), data_);
        begin_ = data_;
    }
    template <typename  InputIt>
    void assign(InputIt first, InputIt last)
    {
        end_ = std::copy(first, last, data_);
        begin_ = data_;
    }
private:
    size_type capacity_;
    size_type maxSize_;
    T *data_;
    iterator begin_;
    iterator end_;
};

template <typename KeyType>
class ConnectionQueue {  // noncopyable
    using MapType = HashMap<int64_t, std::weak_ptr<muduo::net::TcpConnection>>;
    using QueueType = CircularQueue<int64_t>;
public:
    using ValueType = std::weak_ptr<muduo::net::TcpConnection>;
    using size_type = typename MapType::size_type;
    using iterator = typename MapType::iterator;
    using const_iterator = typename MapType::const_iterator;

    ConnectionQueue(size_type map_size, size_type queue_size) :
        map_(map_size),
        q_(queue_size)
    {

    }
    ConnectionQueue(const ConnectionQueue &) = delete;
    ConnectionQueue(ConnectionQueue &&) = delete;  // TODO: movable
    
    size_type size() const 
    {
        return map_.size();
    }
    size_type queueSize() const
    {
        return q_.size();
    }
    size_type maxSize() const 
    {
        return map_.maxSize();
    }
    size_type maxQueueSize() const 
    {
        return q_.maxSize();
    }

    bool empty() const
    {
        return map_.empty();
    }
    bool full() const
    {
        return map_.full();
    }
    bool queueFull() const
    {
        return q_.full();
    }

    KeyType pop()
    {
        bool flag = false;
        KeyType key;
        while (!flag) {
            while (!q_.empty() && map_.find(q_.front()) == map_.end()) {
                q_.pop();
            }
            key = q_.front();
            if (!map_.count(key)) {
                throw std::runtime_error("no tunnel erased");
            } else {
                key = q_.front();
                q_.pop();
                auto sp = map_.at(key).lock();
                if (sp && sp->connected()) {
                    sp->forceClose();
                    flag = true;
                }
                map_.erase(key);
            }
        }
        return key;
    }
    iterator erase(iterator it)
    {
        return map_.erase(it);
    }
    size_type erase(const KeyType &key)
    {
        return map_.erase(key);
    }
    size_type count(const KeyType &key)
    {
        return map_.count(key);
    }
    
    iterator begin() { return map_.begin(); }
    iterator end() { return map_.end(); }
    const_iterator begin() const { return map_.begin(); }
    const_iterator end() const { return map_.end(); }
    const_iterator cbegin() const { return map_.cbegin(); }
    const_iterator cend() const { return map_.cend(); }

    iterator find(const KeyType &key) 
    {
        return map_.find(key);
    }
    ValueType &operator[](const KeyType &key)
    {
        if (q_.full()) {
            cleanQueue();
        }
        q_.push(key);

        return map_[key];
    }

    void cleanMap()
    {
        auto it = map_.begin();
        while(it != map_.end()) {
            auto sp = it->second.lock();
            if (!sp || !sp->connected()) {
                it = map_.erase(it);
            } else {
                ++it;
            }
        }
    }
    void cleanQueue()
    {
        KeyType arr[q_.size()];
        size_type i = 0;
        
        while (!q_.empty()) {
            auto t = q_.front();
            if (map_.count(t)) {
                arr[i++] = t;
            }
            q_.pop();
        }
        q_.assign(arr, arr + i);
    }
// private:
    MapType map_;
    QueueType q_;
};

inline int64_t getNumFromConnName(std::string_view name)
{
    char temp[32];
    auto sv = name.substr(name.rfind("#") + 1);
    assert(sv.size() < sizeof(temp));
    sv.copy(temp, sv.size());
    temp[sv.size()] = '\0';
    return std::stoll(temp);
}
